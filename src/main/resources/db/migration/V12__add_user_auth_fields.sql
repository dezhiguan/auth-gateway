-- S4 协议同意 + S5 账号注销 字段补全
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ NULL;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS terms_version VARCHAR(10) NULL;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS pending_deletion_at TIMESTAMPTZ NULL;
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS deletion_scheduled_at TIMESTAMPTZ NULL;
