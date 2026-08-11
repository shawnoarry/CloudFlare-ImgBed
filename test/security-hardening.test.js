import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { onRequestGet as sessionCheck } from '../functions/api/auth/sessionCheck.js';
import {
    createApiToken,
    getTokenData,
    getTokenPermissions,
} from '../functions/api/manage/apiTokens.js';
import { authenticate, AUTH_SCOPE } from '../functions/utils/auth/authCore.js';
import {
    getProtectedFilePrefixes,
    isAnonymousAccessAllowed,
    isProtectedFileId,
} from '../functions/utils/auth/authPolicy.js';
import {
    preserveUploadConfigSecrets,
    preserveOthersConfigSecrets,
    preserveSecurityConfigSecrets,
    redactOthersConfig,
    redactSecurityConfig,
    redactStoredManagementConfig,
    redactUploadConfig,
} from '../functions/utils/configSecrets.js';
import {
    computeBlobSha256,
    shouldRejectUploadConflict,
    verifyUploadSha256,
} from '../functions/utils/uploadIntegrity.js';

function createDatabase(initial = {}) {
    const values = new Map(Object.entries(initial));
    return {
        values,
        async get(key) {
            return values.has(key) ? values.get(key) : null;
        },
        async put(key, value) {
            values.set(key, value);
        },
        async getWithMetadata(key) {
            return values.has(key) ? { value: values.get(key), metadata: null } : null;
        },
    };
}

function createKv(initial = {}) {
    return createDatabase(initial);
}

describe('authentication policy', () => {
    it('fails closed when no credentials are configured', async () => {
        const env = { img_url: createKv() };
        const result = await authenticate({
            env,
            request: new Request('https://imgbed.example/api/manage/list'),
            requiredPermission: 'list',
            authScope: AUTH_SCOPE.ADMIN,
        });

        assert.equal(result.authorized, false);
        assert.equal(isAnonymousAccessAllowed(env), false);
    });

    it('allows anonymous compatibility only when explicitly enabled', async () => {
        const env = { img_url: createKv(), AUTH_ALLOW_ANONYMOUS: 'true' };
        const result = await authenticate({
            env,
            request: new Request('https://imgbed.example/api/channels'),
            authScope: AUTH_SCOPE.EITHER,
        });

        assert.equal(result.authorized, true);
        assert.equal(result.authType, 'anonymous');
    });

    it('reports authentication as required under the fail-closed default', async () => {
        const response = await sessionCheck({
            request: new Request('https://imgbed.example/api/auth/sessionCheck'),
            env: { img_url: createKv() },
        });
        const body = await response.json();

        assert.equal(body.valid, false);
        assert.equal(body.adminRequired, true);
        assert.equal(body.userRequired, true);
    });
});

describe('upload configuration secrets', () => {
    const stored = {
        huggingface: {
            channels: [{ id: 1, name: 'schat', token: 'hf_secret', repo: 'owner/assets' }],
        },
        s3: {
            channels: [{ id: 2, name: 'archive', accessKeyId: 'key', secretAccessKey: 'secret' }],
        },
    };

    it('redacts credentials from management responses', () => {
        const redacted = redactUploadConfig(stored);

        assert.equal(redacted.huggingface.channels[0].token, '');
        assert.equal(redacted.huggingface.channels[0].tokenConfigured, true);
        assert.equal(redacted.s3.channels[0].secretAccessKey, '');
        assert.equal(JSON.stringify(redacted).includes('hf_secret'), false);
    });

    it('preserves stored credentials when a redacted form is saved', () => {
        const incoming = redactUploadConfig(stored);
        incoming.huggingface.channels[0].repo = 'owner/new-assets';

        const merged = preserveUploadConfigSecrets(incoming, stored);

        assert.equal(merged.huggingface.channels[0].token, 'hf_secret');
        assert.equal(merged.huggingface.channels[0].repo, 'owner/new-assets');
        assert.equal('tokenConfigured' in merged.huggingface.channels[0], false);
    });
});

describe('management configuration secrets', () => {
    it('removes API token records and redacts moderation credentials', () => {
        const stored = {
            auth: {
                user: { authCode: 'user-secret' },
                admin: { adminPassword: 'admin-secret' },
            },
            upload: { moderate: { moderateContentApiKey: 'moderation-secret' } },
            apiTokens: { tokens: { legacy: { token: 'plaintext-token' } } },
        };

        const redacted = redactSecurityConfig(stored);
        assert.equal(redacted.auth.user.authCode, '');
        assert.equal(redacted.auth.user._hasPassword, true);
        assert.equal(redacted.upload.moderate.moderateContentApiKey, '');
        assert.equal(redacted.upload.moderate.moderateContentApiKeyConfigured, true);
        assert.equal('apiTokens' in redacted, false);
        assert.equal(JSON.stringify(redacted).includes('secret'), false);

        const merged = preserveSecurityConfigSecrets(redacted, stored);
        assert.equal(merged.upload.moderate.moderateContentApiKey, 'moderation-secret');
    });

    it('redacts infrastructure secrets and preserves server-owned WebDAV tokens', () => {
        const stored = {
            cloudflareApiToken: { CF_API_KEY: 'cloudflare-secret', CF_ZONE_ID: 'zone' },
            webDAV: {
                enabled: true,
                password: 'webdav-secret',
                internalToken: 'internal-secret',
                internalTokenId: 'internal-id',
            },
        };

        const redacted = redactOthersConfig(stored);
        assert.equal(redacted.cloudflareApiToken.CF_API_KEY, '');
        assert.equal(redacted.cloudflareApiToken.CF_API_KEYConfigured, true);
        assert.equal(redacted.webDAV.password, '');
        assert.equal('internalToken' in redacted.webDAV, false);
        assert.equal('internalTokenId' in redacted.webDAV, false);
        assert.equal(JSON.stringify(redacted).includes('secret'), false);

        redacted.webDAV.internalToken = 'attacker-controlled';
        const merged = preserveOthersConfigSecrets(redacted, stored);
        assert.equal(merged.cloudflareApiToken.CF_API_KEY, 'cloudflare-secret');
        assert.equal(merged.webDAV.password, 'webdav-secret');
        assert.equal(merged.webDAV.internalToken, 'internal-secret');
        assert.equal(merged.webDAV.internalTokenId, 'internal-id');
    });

    it('applies the same redaction to settings backup exports', () => {
        const uploadExport = redactStoredManagementConfig('sysConfig@upload', {
            huggingface: { channels: [{ id: 1, token: 'backup-hf-secret' }] },
        });
        const securityExport = redactStoredManagementConfig('sysConfig@security', {
            auth: { user: { authCode: 'backup-auth-secret' }, admin: {} },
            upload: { moderate: {} },
            apiTokens: { tokens: { legacy: { token: 'backup-token-secret' } } },
        });
        const othersExport = redactStoredManagementConfig('sysConfig@others', {
            webDAV: { internalToken: 'backup-internal-secret' },
        });

        const payload = JSON.stringify({ uploadExport, securityExport, othersExport });
        assert.equal(payload.includes('backup-hf-secret'), false);
        assert.equal(payload.includes('backup-auth-secret'), false);
        assert.equal(payload.includes('backup-token-secret'), false);
        assert.equal(payload.includes('backup-internal-secret'), false);
        assert.equal(uploadExport.huggingface.channels[0].tokenConfigured, true);
        assert.equal('apiTokens' in securityExport, false);
    });
});

describe('API token storage', () => {
    it('stores only a token hash and validates the returned one-time secret', async () => {
        const db = createDatabase();
        const created = await createApiToken(db, 'migration', ['upload', 'list'], 'schatphone');
        const stored = JSON.parse(await db.get('manage@sysConfig@security'));
        const record = stored.apiTokens.tokens[created.id];

        assert.match(created.token, /^imgbed_[a-f0-9]{64}$/);
        assert.equal('token' in record, false);
        assert.match(record.tokenHash, /^[a-f0-9]{64}$/);
        assert.deepEqual(await getTokenPermissions(db, created.token), record.permissions);
        assert.equal((await getTokenData(db, created.token)).tokenPrefix, created.token.slice(0, 15));
    });

    it('migrates a legacy plaintext token after successful validation', async () => {
        const legacyToken = 'imgbed_legacy_secret';
        const db = createDatabase({
            'manage@sysConfig@security': JSON.stringify({
                apiTokens: {
                    tokens: {
                        legacy: {
                            id: 'legacy',
                            name: 'legacy',
                            token: legacyToken,
                            owner: 'test',
                            permissions: ['list'],
                        },
                    },
                },
            }),
        });

        assert.deepEqual(await getTokenPermissions(db, legacyToken), ['list']);
        const migrated = JSON.parse(await db.get('manage@sysConfig@security')).apiTokens.tokens.legacy;
        assert.equal('token' in migrated, false);
        assert.match(migrated.tokenHash, /^[a-f0-9]{64}$/);
    });
});

describe('protected file policy', () => {
    it('protects the SchatPhone source prefix by default', () => {
        assert.deepEqual(getProtectedFilePrefixes({}), ['schatphone-source']);
        assert.equal(isProtectedFileId('schatphone-source/batch/master.png', {}), true);
        assert.equal(isProtectedFileId('public/runtime.png', {}), false);
    });

    it('accepts an explicit comma-separated prefix list', () => {
        const env = { PROTECTED_FILE_PREFIXES: 'masters, private/source/' };
        assert.equal(isProtectedFileId('private/source/file.png', env), true);
        assert.equal(isProtectedFileId('schatphone-source/file.png', env), false);
    });
});

describe('protected upload integrity', () => {
    it('verifies a matching SHA-256 and rejects mismatches', async () => {
        const file = new Blob(['schatphone-master']);
        const hash = await computeBlobSha256(file);

        assert.equal(await verifyUploadSha256(file, hash, { required: true }), hash);
        await assert.rejects(
            verifyUploadSha256(file, '0'.repeat(64), { required: true }),
            error => error.status === 422,
        );
    });

    it('requires a hash for protected uploads', async () => {
        await assert.rejects(
            verifyUploadSha256(new Blob(['data']), null, { required: true }),
            error => error.status === 400,
        );
    });

    it('rejects an existing protected file id instead of renaming it', () => {
        const fileId = 'schatphone-source/batch/master.png';
        const url = new URL('https://imgbed.example/upload?uploadNameType=origin');

        assert.equal(shouldRejectUploadConflict(fileId, url, {}), true);
        assert.equal(shouldRejectUploadConflict('public/master.png', url, {}), false);
    });
});
