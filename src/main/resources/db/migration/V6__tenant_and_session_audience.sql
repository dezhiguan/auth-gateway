ALTER TABLE auth_users ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '';

UPDATE auth_users SET tenant_id = 'tn_user_' || id WHERE tenant_id = '';

ALTER TABLE auth_users ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE auth_sessions ADD COLUMN target_audience VARCHAR(64);

UPDATE auth_sessions SET target_audience = device_id WHERE target_audience IS NULL;

CREATE INDEX idx_auth_users_tenant ON auth_users(tenant_id);
