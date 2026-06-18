CREATE TABLE auth_users (
    id BIGSERIAL PRIMARY KEY,
    phone_hash VARCHAR(64),
    email_hash VARCHAR(64),
    username VARCHAR(64),
    password_hash VARCHAR(255),
    platform_role VARCHAR(32) NOT NULL DEFAULT 'USER',
    session_version BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_users_phone_hash ON auth_users(phone_hash);
CREATE INDEX idx_auth_users_email_hash ON auth_users(email_hash);

CREATE TABLE auth_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth_users(id),
    device_id VARCHAR(64),
    session_version BIGINT NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);

CREATE TABLE refresh_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,
    family_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64) NOT NULL REFERENCES auth_sessions(session_id),
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id);

CREATE TABLE oauth_clients (
    client_id VARCHAR(64) PRIMARY KEY,
    client_name VARCHAR(128) NOT NULL,
    auth_method VARCHAR(64) NOT NULL,
    secret_hash VARCHAR(255),
    jwks_uri VARCHAR(512),
    allowed_grant_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_audiences JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
);

CREATE TABLE agent_consents (
    consent_id VARCHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth_users(id),
    client_principal_id VARCHAR(64) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_kb_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_agent_consents_user_id ON agent_consents(user_id);
CREATE INDEX idx_agent_consents_client_principal_id ON agent_consents(client_principal_id);

CREATE TABLE event_subscriptions (
    id BIGSERIAL PRIMARY KEY,
    subscriber VARCHAR(128) NOT NULL,
    event_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    endpoint_url VARCHAR(512) NOT NULL,
    hmac_key_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
);

CREATE TABLE sms_codes (
    id BIGSERIAL PRIMARY KEY,
    phone_hash VARCHAR(64) NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    scene VARCHAR(32) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_sms_codes_phone_scene ON sms_codes(phone_hash, scene);
CREATE INDEX idx_sms_codes_expires_at ON sms_codes(expires_at);

CREATE TABLE jti_blacklist (
    jti VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_jti_blacklist_expires_at ON jti_blacklist(expires_at);
