export const MAX_BATCH_FILES = 10;
export const MAX_BATCH_BYTES = 40 * 1024 * 1024;

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const FIELD_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

export class BatchUploadError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.name = 'BatchUploadError';
        this.status = status;
    }
}

export function normalizeBatchFileId(value) {
    const fileId = String(value || '').trim().replaceAll('\\', '/').replace(/^\/+/, '');
    if (!fileId || fileId.endsWith('/') || /[\u0000-\u001f\u007f%?#]/.test(fileId)) {
        throw new BatchUploadError('Batch file id is invalid');
    }

    const segments = fileId.split('/');
    if (segments.some(segment => !segment || segment === '.' || segment === '..')) {
        throw new BatchUploadError('Batch file id contains an unsafe path segment');
    }
    return segments.join('/');
}

export function parseBatchManifest(value) {
    let manifest;
    try {
        manifest = typeof value === 'string' ? JSON.parse(value) : value;
    } catch {
        throw new BatchUploadError('Batch manifest must be valid JSON');
    }

    const batchId = String(manifest?.batchId || '').trim();
    const files = manifest?.files;
    if (!batchId || batchId.length > 128 || !Array.isArray(files) || files.length === 0) {
        throw new BatchUploadError('Batch manifest requires a batchId and files');
    }
    if (files.length > MAX_BATCH_FILES) {
        throw new BatchUploadError(`Batch supports at most ${MAX_BATCH_FILES} files`, 413);
    }

    const fieldNames = new Set();
    const fileIds = new Set();
    const normalizedFiles = files.map(entry => {
        const field = String(entry?.field || '').trim();
        const fileId = normalizeBatchFileId(entry?.fileId);
        const sha256 = String(entry?.sha256 || '').trim().toLowerCase();
        if (!FIELD_PATTERN.test(field) || !SHA256_PATTERN.test(sha256)) {
            throw new BatchUploadError('Each batch entry requires a valid field and SHA-256');
        }
        if (fieldNames.has(field) || fileIds.has(fileId)) {
            throw new BatchUploadError('Batch fields and file ids must be unique');
        }
        fieldNames.add(field);
        fileIds.add(fileId);
        return { field, fileId, sha256 };
    });

    return { batchId, files: normalizedFiles };
}

export function assertBatchByteLimit(files) {
    const totalBytes = files.reduce((sum, file) => sum + Number(file?.size || 0), 0);
    if (totalBytes <= 0 || totalBytes > MAX_BATCH_BYTES) {
        throw new BatchUploadError(`Batch supports at most ${MAX_BATCH_BYTES} bytes`, 413);
    }
    return totalBytes;
}

export function buildDeterministicHfPath(fileId, sha256) {
    const normalized = normalizeBatchFileId(fileId);
    const slashIndex = normalized.lastIndexOf('/');
    const directory = slashIndex === -1 ? '' : normalized.slice(0, slashIndex + 1);
    const fileName = slashIndex === -1 ? normalized : normalized.slice(slashIndex + 1);
    return `${directory}${sha256.slice(0, 16)}_${fileName}`;
}
