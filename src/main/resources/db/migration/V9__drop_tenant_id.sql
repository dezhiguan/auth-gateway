-- 去掉租户模型：auth_users.tenant_id 不再用于身份/鉴权（CareerMate 纯个人化，RAG 改用个人/组织 owner 模型）。
-- tenant_id 历史上仅作命名空间字符串，无访问控制依赖，可安全删除。
DROP INDEX IF EXISTS idx_auth_users_tenant;

ALTER TABLE auth_users DROP COLUMN IF EXISTS tenant_id;
