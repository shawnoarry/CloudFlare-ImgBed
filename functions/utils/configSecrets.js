export const REDACTED_SECRET = '__IMG_BED_SECRET_REDACTED__';

const SECRET_FIELDS = {
    telegram: ['botToken'],
    s3: ['accessKeyId', 'secretAccessKey'],
    discord: ['botToken'],
    huggingface: ['token'],
    webdav: ['password'],
};

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value));
}

function findMatchingChannel(channels, candidate) {
    return channels.find(channel => (
        candidate.id != null && channel.id === candidate.id
    )) || channels.find(channel => (
        candidate.name && channel.name === candidate.name
    ));
}

function redactField(target, field) {
    if (target?.[field]) {
        target[field] = '';
        target[`${field}Configured`] = true;
    }
}

function preserveField(incoming, stored, field) {
    if (!incoming) return;

    if (incoming[field] === REDACTED_SECRET || incoming[field] === '' || incoming[field] == null) {
        if (stored?.[field]) {
            incoming[field] = stored[field];
        } else {
            delete incoming[field];
        }
    }
    delete incoming[`${field}Configured`];
}

export function redactUploadConfig(config) {
    const redacted = clone(config) || {};

    for (const [sectionName, fields] of Object.entries(SECRET_FIELDS)) {
        const channels = redacted[sectionName]?.channels || [];
        for (const channel of channels) {
            for (const field of fields) {
                redactField(channel, field);
            }
        }
    }

    return redacted;
}

export function preserveUploadConfigSecrets(incomingConfig, storedConfig) {
    const incoming = clone(incomingConfig) || {};
    const stored = storedConfig || {};

    for (const [sectionName, fields] of Object.entries(SECRET_FIELDS)) {
        const incomingChannels = incoming[sectionName]?.channels || [];
        const storedChannels = stored[sectionName]?.channels || [];

        for (const channel of incomingChannels) {
            const previous = findMatchingChannel(storedChannels, channel);
            for (const field of fields) {
                preserveField(channel, previous, field);
            }
        }
    }

    return incoming;
}

export function redactSecurityConfig(config) {
    const redacted = clone(config) || {};

    redactField(redacted.auth?.user, 'authCode');
    if (redacted.auth?.user?.authCodeConfigured) {
        redacted.auth.user._hasPassword = true;
        delete redacted.auth.user.authCodeConfigured;
    }

    redactField(redacted.auth?.admin, 'adminPassword');
    if (redacted.auth?.admin?.adminPasswordConfigured) {
        redacted.auth.admin._hasPassword = true;
        delete redacted.auth.admin.adminPasswordConfigured;
    }

    redactField(redacted.upload?.moderate, 'moderateContentApiKey');
    delete redacted.apiTokens;

    return redacted;
}

export function preserveSecurityConfigSecrets(incomingConfig, storedConfig) {
    const incoming = clone(incomingConfig) || {};
    preserveField(
        incoming.upload?.moderate,
        storedConfig?.upload?.moderate,
        'moderateContentApiKey',
    );
    return incoming;
}

export function redactOthersConfig(config) {
    const redacted = clone(config) || {};

    redactField(redacted.cloudflareApiToken, 'CF_API_KEY');
    redactField(redacted.webDAV, 'password');
    if (redacted.webDAV) {
        delete redacted.webDAV.internalToken;
        delete redacted.webDAV.internalTokenId;
    }

    return redacted;
}

export function preserveOthersConfigSecrets(incomingConfig, storedConfig) {
    const incoming = clone(incomingConfig) || {};
    const stored = storedConfig || {};

    preserveField(incoming.cloudflareApiToken, stored.cloudflareApiToken, 'CF_API_KEY');
    preserveField(incoming.webDAV, stored.webDAV, 'password');

    if (incoming.webDAV) {
        if (stored.webDAV?.internalToken) {
            incoming.webDAV.internalToken = stored.webDAV.internalToken;
        } else {
            delete incoming.webDAV.internalToken;
        }
        if (stored.webDAV?.internalTokenId) {
            incoming.webDAV.internalTokenId = stored.webDAV.internalTokenId;
        } else {
            delete incoming.webDAV.internalTokenId;
        }
    }

    return incoming;
}

export function redactStoredManagementConfig(settingKey, value) {
    switch (settingKey) {
        case 'sysConfig@upload':
            return redactUploadConfig(value);
        case 'sysConfig@security':
            return redactSecurityConfig(value);
        case 'sysConfig@others':
            return redactOthersConfig(value);
        default:
            return clone(value);
    }
}
