-- 应用级注销：user_app_membership 支持"该 App 冷静期注销"。
-- status 取值扩展为 ACTIVE | PENDING_DELETION | DELETED；新增计划清理时间列。
ALTER TABLE user_app_membership ADD COLUMN IF NOT EXISTS pending_deletion_at TIMESTAMPTZ NULL;
ALTER TABLE user_app_membership ADD COLUMN IF NOT EXISTS deletion_scheduled_at TIMESTAMPTZ NULL;

-- 到期清理扫描用索引。
CREATE INDEX IF NOT EXISTS idx_user_app_membership_deletion
    ON user_app_membership(status, deletion_scheduled_at);
