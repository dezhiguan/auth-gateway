-- 控制台登录专用客户端。只允许密码、短信和刷新，不能换票，受众只有 keel-console。
INSERT INTO oauth_clients (
    client_id,
    client_name,
    auth_method,
    secret_hash,
    jwks_uri,
    allowed_grant_types,
    allowed_audiences,
    status
) VALUES (
    'keel-console-backend',
    'Keel Console Backend',
    'private_key_jwt',
    NULL,
    'http://keel-server.keel-system.svc.cluster.local:8080/api/v1/auth/jwks.json',
    '["password", "mobile", "refresh_token"]'::jsonb,
    '["keel-console"]'::jsonb,
    'ACTIVE'
) ON CONFLICT (client_id) DO UPDATE
SET client_name = EXCLUDED.client_name,
    auth_method = EXCLUDED.auth_method,
    jwks_uri = EXCLUDED.jwks_uri,
    allowed_grant_types = EXCLUDED.allowed_grant_types,
    allowed_audiences = EXCLUDED.allowed_audiences,
    status = EXCLUDED.status;
