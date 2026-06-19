ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE oauth_clients
SET allowed_audiences = '["careermate-api", "ragforge-admin-api", "ragforge-api"]'::jsonb,
    allowed_scopes = '["rag:search"]'::jsonb
WHERE client_id = 'careermate-backend';

UPDATE oauth_clients
SET allowed_scopes = '["rag:admin:read", "rag:admin:write"]'::jsonb
WHERE client_id = 'ragforge-admin-backend';
