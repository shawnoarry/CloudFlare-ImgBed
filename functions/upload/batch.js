import { userAuthCheck, UnauthorizedResponse } from '../utils/auth/userAuth.js';
import { getDatabase } from '../utils/databaseAdapter.js';
import { batchAddFilesToIndex } from '../utils/indexManager.js';
import { HuggingFaceAPI } from '../utils/storage/huggingfaceAPI.js';
import { fetchSecurityConfig, fetchUploadConfig } from '../utils/sysConfig.js';
import {
    assertBatchByteLimit,
    BatchUploadError,
    buildDeterministicHfPath,
    parseBatchManifest,
} from '../utils/batchUpload.js';
import { verifyUploadSha256 } from '../utils/uploadIntegrity.js';
import {
    createResponse,
    getImageDimensions,
    getIPAddress,
    getUploadIp,
    isBlockedUploadIp,
    purgeCDNCache,
} from './uploadTools.js';

function jsonResponse(payload, status = 200) {
    return createResponse(JSON.stringify(payload), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

function fileNameFromId(fileId) {
    return fileId.slice(fileId.lastIndexOf('/') + 1);
}

function directoryFromId(fileId) {
    const slashIndex = fileId.lastIndexOf('/');
    return slashIndex === -1 ? '' : `${fileId.slice(0, slashIndex)}/`;
}

function existingFileMatches(record, entry, file) {
    const metadata = record?.metadata;
    return metadata?.SHA256 === entry.sha256
        && Number(metadata?.FileSizeBytes) === file.size;
}

function selectHuggingFaceChannel(uploadConfig, channelName) {
    const settings = uploadConfig?.huggingface;
    const channels = settings?.channels || [];
    if (channelName) {
        return channels.find(channel => channel.name === channelName) || null;
    }
    return channels[0] || null;
}

async function createMetadata(file, fileId, sha256, batchId, uploadIp, uploadAddress) {
    let imageDimensions = null;
    if (file.type.startsWith('image/')) {
        try {
            const headerBuffer = await file.slice(0, 65536).arrayBuffer();
            imageDimensions = getImageDimensions(headerBuffer, file.type);
        } catch (error) {
            console.warn(`Failed to inspect image dimensions for ${fileId}:`, error.message);
        }
    }

    const metadata = {
        FileName: fileNameFromId(fileId),
        FileType: file.type || 'application/octet-stream',
        FileSize: (file.size / 1024 / 1024).toFixed(2),
        FileSizeBytes: file.size,
        UploadIP: uploadIp,
        UploadAddress: uploadAddress,
        ListType: 'None',
        TimeStamp: Date.now(),
        Label: 'None',
        Directory: directoryFromId(fileId),
        Tags: [],
        SHA256: sha256,
        BatchId: batchId,
    };

    if (imageDimensions) {
        metadata.Width = imageDimensions.width;
        metadata.Height = imageDimensions.height;
    }
    return metadata;
}

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method !== 'POST') {
        return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    const url = new URL(request.url);
    context.url = url;
    if (!await userAuthCheck(env, url, request, 'upload')) {
        return UnauthorizedResponse('Unauthorized');
    }

    const uploadIp = getUploadIp(request);
    if (await isBlockedUploadIp(env, uploadIp)) {
        return jsonResponse({ error: 'Your IP is blocked' }, 403);
    }

    try {
        const formData = await request.formData();
        const manifest = parseBatchManifest(formData.get('manifest'));
        const files = manifest.files.map(entry => {
            const file = formData.get(entry.field);
            if (!(file instanceof Blob)) {
                throw new BatchUploadError(`Missing file field: ${entry.field}`);
            }
            return { ...entry, file };
        });
        const totalBytes = assertBatchByteLimit(files.map(entry => entry.file));

        const securityConfig = await fetchSecurityConfig(env);
        if (securityConfig.upload?.moderate?.enabled) {
            throw new BatchUploadError('Batch upload is unavailable while content moderation is enabled', 409);
        }

        const uploadConfig = await fetchUploadConfig(env, context);
        const channel = selectHuggingFaceChannel(uploadConfig, url.searchParams.get('channelName'));
        if (!channel?.token || !channel?.repo) {
            throw new BatchUploadError('HuggingFace channel is not configured', 400);
        }

        const db = getDatabase(env);
        const uploadAddress = await getIPAddress(env, uploadIp, securityConfig);
        const pending = [];
        const indexEntries = [];
        const results = new Map();

        // Complete all integrity and conflict checks before uploading any bytes.
        for (const entry of files) {
            await verifyUploadSha256(entry.file, entry.sha256, { required: true });
            const existing = await db.getWithMetadata(entry.fileId);
            if (existing && (existing.value !== null || existing.metadata)) {
                if (!existingFileMatches(existing, entry, entry.file)) {
                    throw new BatchUploadError(`File already exists with different content: ${entry.fileId}`, 409);
                }
                results.set(entry.fileId, {
                    fileId: entry.fileId,
                    bytes: entry.file.size,
                    sha256: entry.sha256,
                    status: 'already-uploaded',
                    src: `/file/${entry.fileId}`,
                });
                indexEntries.push({ fileId: entry.fileId, metadata: existing.metadata });
                continue;
            }

            const metadata = await createMetadata(
                entry.file,
                entry.fileId,
                entry.sha256,
                manifest.batchId,
                uploadIp,
                uploadAddress,
            );
            const hfFilePath = buildDeterministicHfPath(entry.fileId, entry.sha256);
            metadata.Channel = 'HuggingFace';
            metadata.ChannelName = channel.name || 'HuggingFace_env';
            metadata.HfFilePath = hfFilePath;
            pending.push({ ...entry, metadata, hfFilePath });
            indexEntries.push({ fileId: entry.fileId, metadata });
        }

        let commit = null;
        if (pending.length > 0) {
            const huggingFace = new HuggingFaceAPI(
                channel.token,
                channel.repo,
                channel.isPrivate || false,
            );
            const uploadResult = await huggingFace.uploadFiles(
                pending.map(entry => ({
                    file: entry.file,
                    filePath: entry.hfFilePath,
                    sha256: entry.sha256,
                })),
                `Upload batch ${manifest.batchId}`,
            );
            commit = uploadResult.commit;

            for (const entry of pending) {
                await db.put(entry.fileId, '', { metadata: entry.metadata });
                results.set(entry.fileId, {
                    fileId: entry.fileId,
                    bytes: entry.file.size,
                    sha256: entry.sha256,
                    status: 'uploaded',
                    src: `/file/${entry.fileId}`,
                });
            }

            context.waitUntil(Promise.all(pending.map(entry => (
                purgeCDNCache(env, `${url.origin}/file/${entry.fileId}`, url, directoryFromId(entry.fileId))
            ))));
        }

        // Re-index matching existing files as well so a retry repairs a prior post-upload index failure.
        const indexResult = await batchAddFilesToIndex(context, indexEntries);
        if (!indexResult.success) {
            throw new Error(`Failed to update file index: ${indexResult.error}`);
        }

        return jsonResponse({
            batchId: manifest.batchId,
            totalFiles: files.length,
            totalBytes,
            committedFiles: pending.length,
            commit,
            results: manifest.files.map(entry => results.get(entry.fileId)),
        });
    } catch (error) {
        if (!error.status || error.status >= 500) {
            console.error('Batch upload failed:', error.message);
        }
        return jsonResponse({ error: error.message }, error.status || 500);
    }
}
