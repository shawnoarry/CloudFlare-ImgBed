import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';

import {
    assertBatchByteLimit,
    BatchUploadError,
    buildDeterministicHfPath,
    MAX_BATCH_BYTES,
    MAX_BATCH_FILES,
    parseBatchManifest,
} from '../functions/utils/batchUpload.js';
import { HuggingFaceAPI } from '../functions/utils/storage/huggingfaceAPI.js';
import { onRequest as batchUpload } from '../functions/upload/batch.js';
import { createApiToken } from '../functions/api/manage/apiTokens.js';
import { getDatabase } from '../functions/utils/databaseAdapter.js';

function createKv() {
    const values = new Map();
    return {
        values,
        async get(key) {
            return values.get(key)?.value ?? null;
        },
        async getWithMetadata(key) {
            return values.get(key) || null;
        },
        async put(key, value, options = {}) {
            values.set(key, { value, metadata: options.metadata || null });
        },
        async delete(key) {
            values.delete(key);
        },
        async list(options = {}) {
            const prefix = options.prefix || '';
            return {
                keys: [...values.keys()]
                    .filter(key => key.startsWith(prefix))
                    .map(name => ({ name })),
                cursor: null,
            };
        },
    };
}

function digest(value) {
    return createHash('sha256').update(value).digest('hex');
}

function batchRequest(token, files) {
    const formData = new FormData();
    const manifest = {
        batchId: 'poster-batch',
        files: files.map((entry, index) => ({
            field: `file-${index}`,
            fileId: entry.fileId,
            sha256: digest(entry.content),
        })),
    };
    formData.set('manifest', JSON.stringify(manifest));
    files.forEach((entry, index) => {
        formData.set(`file-${index}`, new Blob([entry.content], { type: entry.type }), entry.name);
    });
    return new Request('https://imgbed.example/upload/batch', {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
    });
}

function requestContext(request, env) {
    const background = [];
    return {
        context: {
            request,
            env,
            data: {},
            params: {},
            waitUntil(promise) {
                background.push(Promise.resolve(promise));
            },
        },
        background,
    };
}

describe('batch upload manifest', () => {
    it('normalizes a valid multi-file manifest', () => {
        const digestA = 'a'.repeat(64);
        const digestB = 'b'.repeat(64);
        const parsed = parseBatchManifest(JSON.stringify({
            batchId: 'poster-2026-08-11',
            files: [
                { field: 'file-0', fileId: '/schatphone-assets/poster.png', sha256: digestA },
                { field: 'file-1', fileId: 'schatphone-source/poster.png', sha256: digestB },
            ],
        }));

        assert.equal(parsed.files.length, 2);
        assert.equal(parsed.files[0].fileId, 'schatphone-assets/poster.png');
        assert.equal(parsed.files[1].sha256, digestB);
    });

    it('rejects duplicate ids, unsafe paths, and oversized manifests', () => {
        const digest = 'a'.repeat(64);
        assert.throws(() => parseBatchManifest({
            batchId: 'duplicate',
            files: [
                { field: 'file-0', fileId: 'same.png', sha256: digest },
                { field: 'file-1', fileId: 'same.png', sha256: digest },
            ],
        }), BatchUploadError);
        assert.throws(() => parseBatchManifest({
            batchId: 'unsafe',
            files: [{ field: 'file-0', fileId: '../secret.png', sha256: digest }],
        }), BatchUploadError);
        assert.throws(() => parseBatchManifest({
            batchId: 'too-many',
            files: Array.from({ length: MAX_BATCH_FILES + 1 }, (_, index) => ({
                field: `file-${index}`,
                fileId: `${index}.png`,
                sha256: digest,
            })),
        }), error => error instanceof BatchUploadError && error.status === 413);
    });

    it('uses a bounded body and deterministic Hugging Face path', () => {
        assert.equal(assertBatchByteLimit([{ size: 10 }, { size: 20 }]), 30);
        assert.throws(
            () => assertBatchByteLimit([{ size: MAX_BATCH_BYTES + 1 }]),
            error => error instanceof BatchUploadError && error.status === 413,
        );
        assert.equal(
            buildDeterministicHfPath('schatphone-assets/poster.png', 'a'.repeat(64)),
            'schatphone-assets/aaaaaaaaaaaaaaaa_poster.png',
        );
    });
});

describe('Hugging Face batch commit', () => {
    it('publishes multiple direct files with one commit request', async () => {
        const originalFetch = globalThis.fetch;
        const requests = [];
        globalThis.fetch = async (url, init = {}) => {
            requests.push({ url: String(url), init });
            if (String(url).endsWith('/api/datasets/owner/assets') && !init.method) {
                return new Response('{}', { status: 200 });
            }
            if (String(url).includes('/preupload/main')) {
                return Response.json({ files: [{ uploadMode: 'regular' }] });
            }
            if (String(url).includes('/commit/main')) {
                return Response.json({ commitUrl: 'https://huggingface.co/commit/one' });
            }
            throw new Error(`Unexpected request: ${url}`);
        };

        try {
            const api = new HuggingFaceAPI('test-token', 'owner/assets');
            const result = await api.uploadFiles([
                {
                    file: new Blob(['poster']),
                    filePath: 'schatphone-assets/poster.png',
                    sha256: 'a'.repeat(64),
                },
                {
                    file: new Blob(['thumbnail']),
                    filePath: 'schatphone-assets/poster-thumb.webp',
                    sha256: 'b'.repeat(64),
                },
            ], 'Upload poster batch');

            const commits = requests.filter(request => request.url.includes('/commit/main'));
            assert.equal(commits.length, 1);
            const operations = commits[0].init.body.split('\n').map(line => JSON.parse(line));
            assert.equal(operations.length, 3);
            assert.equal(operations[0].key, 'header');
            assert.deepEqual(operations.slice(1).map(operation => operation.value.path), [
                'schatphone-assets/poster.png',
                'schatphone-assets/poster-thumb.webp',
            ]);
            assert.equal(result.files.length, 2);
        } finally {
            globalThis.fetch = originalFetch;
        }
    });
});

describe('batch upload endpoint', () => {
    it('requires upload auth, commits once, resumes, and rejects conflicts', async () => {
        const kv = createKv();
        const env = {
            img_url: kv,
            HF_TOKEN: 'hf-test-token',
            HF_REPO: 'owner/assets',
            HF_PRIVATE: 'true',
        };
        const created = await createApiToken(
            getDatabase(env),
            'project-publisher',
            ['upload', 'list'],
            'schatphone',
        );
        const files = [
            {
                name: 'poster.png',
                fileId: 'schatphone-assets/poster.png',
                content: 'poster',
                type: 'image/png',
            },
            {
                name: 'poster-master.png',
                fileId: 'schatphone-source/poster-master.png',
                content: 'poster-master',
                type: 'image/png',
            },
        ];

        const unauthorized = requestContext(batchRequest('', files), env);
        assert.equal((await batchUpload(unauthorized.context)).status, 401);

        const originalFetch = globalThis.fetch;
        const originalCaches = globalThis.caches;
        const requests = [];
        globalThis.caches = {
            default: {
                async delete() {
                    return true;
                },
                async put() {},
            },
        };
        globalThis.fetch = async (url, init = {}) => {
            requests.push({ url: String(url), init });
            if (String(url).endsWith('/api/datasets/owner/assets') && !init.method) {
                return new Response('{}', { status: 200 });
            }
            if (String(url).includes('/preupload/main')) {
                return Response.json({ files: [{ uploadMode: 'regular' }] });
            }
            if (String(url).includes('/commit/main')) {
                return Response.json({ commitUrl: 'https://huggingface.co/commit/batch' });
            }
            return new Response('', { status: 204 });
        };

        try {
            const first = requestContext(batchRequest(created.token, files), env);
            const firstResponse = await batchUpload(first.context);
            const firstBody = await firstResponse.json();
            await Promise.all(first.background);

            assert.equal(firstResponse.status, 200);
            assert.equal(firstBody.committedFiles, 2);
            assert.equal(firstBody.results.every(result => result.status === 'uploaded'), true);
            assert.equal(
                requests.filter(request => request.url.includes('/commit/main')).length,
                1,
            );
            assert.equal(
                kv.values.get('schatphone-source/poster-master.png').metadata.SHA256,
                digest('poster-master'),
            );

            for (const key of [...kv.values.keys()]) {
                if (key.startsWith('manage@index')) kv.values.delete(key);
            }

            const requestCountBeforeResume = requests.length;
            const resumed = requestContext(batchRequest(created.token, files), env);
            const resumedResponse = await batchUpload(resumed.context);
            const resumedBody = await resumedResponse.json();

            assert.equal(resumedResponse.status, 200);
            assert.equal(resumedBody.committedFiles, 0);
            assert.equal(
                resumedBody.results.every(result => result.status === 'already-uploaded'),
                true,
            );
            assert.equal(requests.length, requestCountBeforeResume);
            const repairedIndex = await getDatabase(env).list({ prefix: 'manage@index' });
            assert.equal(repairedIndex.keys.length > 0, true);

            const conflictFiles = [{
                ...files[0],
                content: 'different-poster',
            }];
            const conflict = requestContext(batchRequest(created.token, conflictFiles), env);
            const conflictResponse = await batchUpload(conflict.context);
            assert.equal(conflictResponse.status, 409);
        } finally {
            globalThis.fetch = originalFetch;
            globalThis.caches = originalCaches;
        }
    });
});
