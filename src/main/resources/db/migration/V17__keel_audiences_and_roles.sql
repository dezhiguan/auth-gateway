CREATE TABLE audience_scopes (
    audience VARCHAR(64) NOT NULL,
    scope VARCHAR(128) NOT NULL,
    required_platform_role VARCHAR(32),
    PRIMARY KEY (audience, scope)
);

INSERT INTO audience_scopes(audience, scope, required_platform_role) VALUES
    ('careermate-api', 'rag:search', NULL),
    ('ragforge-admin-api', 'rag:admin:read', NULL),
    ('ragforge-admin-api', 'rag:admin:write', 'ADMIN'),
    ('keel-api', 'agent:invoke', NULL),
    ('keel-api', 'rag:search', NULL);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    role VARCHAR(64) NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE INDEX idx_user_roles_role ON user_roles(role);

ALTER TABLE oauth_clients ADD COLUMN keel_managed BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE oauth_clients
SET allowed_audiences = allowed_audiences || '["keel-api"]'::jsonb
WHERE client_id = 'careermate-backend'
  AND NOT allowed_audiences ? 'keel-api';
