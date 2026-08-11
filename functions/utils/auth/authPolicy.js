const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);

function parseList(value) {
    return String(value || '')
        .split(',')
        .map(item => item.trim().replace(/^\/+|\/+$/g, ''))
        .filter(Boolean);
}

export function isAnonymousAccessAllowed(env = {}) {
    return TRUE_VALUES.has(String(env.AUTH_ALLOW_ANONYMOUS || '').trim().toLowerCase());
}

export function getProtectedFilePrefixes(env = {}) {
    const configured = parseList(env.PROTECTED_FILE_PREFIXES);
    return configured.length > 0 ? configured : ['schatphone-source'];
}

export function isProtectedFileId(fileId, env = {}) {
    const normalized = String(fileId || '').replace(/^\/+/, '');
    return getProtectedFilePrefixes(env).some(prefix => (
        normalized === prefix || normalized.startsWith(`${prefix}/`)
    ));
}
