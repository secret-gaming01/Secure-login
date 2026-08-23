-- Secure-login schema (PostgreSQL)
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT,
    salt TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_login_ip TEXT,
    last_login_country TEXT,
    last_login_device TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_last_ip ON users (last_login_ip);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_hash TEXT NOT NULL,
    device TEXT,
    fingerprint TEXT,
    ip TEXT,
    country TEXT,
    city TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh ON sessions (refresh_hash);

CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    kind TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    meta TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_value ON tokens (value_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_user_kind ON tokens (user_id, kind);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    mode TEXT NOT NULL,
    reason TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    CONSTRAINT uq_blocked_ip UNIQUE (ip)
);

CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    credential_id TEXT NOT NULL,
    public_key_enc TEXT NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    transports TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    CONSTRAINT uq_passkey_cred UNIQUE (credential_id)
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys (user_id);

CREATE TABLE IF NOT EXISTS mfa (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_codes_enc TEXT,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS security_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    event TEXT NOT NULL,
    severity TEXT NOT NULL,
    ip TEXT,
    country TEXT,
    details_enc TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_created ON security_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_event ON security_logs (event);

CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY,
    email TEXT,
    ip TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_time ON login_attempts (ip, created_at);
CREATE INDEX IF NOT EXISTS idx_attempts_email_time ON login_attempts (email, created_at);

CREATE TABLE IF NOT EXISTS revoked_jti (
    jti TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
