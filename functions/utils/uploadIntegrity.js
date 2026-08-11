import { isProtectedFileId } from './auth/authPolicy.js';

const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export class UploadIntegrityError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.name = 'UploadIntegrityError';
        this.status = status;
    }
}

export async function computeBlobSha256(blob) {
    const data = await blob.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

export async function verifyUploadSha256(file, suppliedSha256, { required = false } = {}) {
    const normalized = String(suppliedSha256 || '').trim().toLowerCase();
    if (!normalized) {
        if (required) {
            throw new UploadIntegrityError('SHA-256 is required for protected uploads');
        }
        return null;
    }

    if (!SHA256_PATTERN.test(normalized)) {
        throw new UploadIntegrityError('SHA-256 must be a 64-character hexadecimal value');
    }

    const actual = await computeBlobSha256(file);
    if (actual !== normalized) {
        throw new UploadIntegrityError('Uploaded file does not match the supplied SHA-256', 422);
    }

    return actual;
}

export function shouldRejectUploadConflict(fileId, url, env = {}) {
    return url.searchParams.get('onConflict') === 'reject' || isProtectedFileId(fileId, env);
}
