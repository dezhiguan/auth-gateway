INSERT INTO oauth_clients (
    client_id,
    client_name,
    auth_method,
    secret_hash,
    jwks_uri,
    allowed_grant_types,
    allowed_audiences,
    status
) VALUES
(
    'careermate-backend',
    'CareerMate Backend',
    'private_key_jwt',
    NULL,
    'https://careermate.cn/.well-known/jwks.json',
    '["password", "mobile", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"]'::jsonb,
    '["careermate-api", "ragforge-admin-api"]'::jsonb,
    'ACTIVE'
),
(
    'ragforge-admin-backend',
    'RAGForge Admin Backend',
    'private_key_jwt',
    NULL,
    'https://admin.ragforge.cn/.well-known/jwks.json',
    '["password", "mobile", "refresh_token"]'::jsonb,
    '["ragforge-admin-api"]'::jsonb,
    'ACTIVE'
);
