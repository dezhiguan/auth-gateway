-- 统一认证改造 V1：账号标识唯一约束 + 应用准入(membership)
-- 设计依据：rag-forge/docs/unified-auth-redesign-V1.html 第 3/5/7 节

-- 1) 账号标识全局唯一。phone_hash / email_hash / username 可空，
--    使用部分唯一索引：仅对非空值强制唯一，允许多行为 NULL。
DROP INDEX IF EXISTS idx_auth_users_phone_hash;
DROP INDEX IF EXISTS idx_auth_users_email_hash;

CREATE UNIQUE INDEX uq_auth_users_phone_hash ON auth_users(phone_hash) WHERE phone_hash IS NOT NULL;
CREATE UNIQUE INDEX uq_auth_users_email_hash ON auth_users(email_hash) WHERE email_hash IS NOT NULL;
CREATE UNIQUE INDEX uq_auth_users_username ON auth_users(username) WHERE username IS NOT NULL;

-- 2) 应用准入：一行一个 App（careermate / ragforge）。
--    "注册来源/能进哪个 App、以什么角色" 由本表表达，而非在 auth_users 上塞会变化的来源字段。
CREATE TABLE user_app_membership (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES auth_users(id),
    app VARCHAR(32) NOT NULL,                 -- 'careermate' | 'ragforge'
    role VARCHAR(32) NOT NULL DEFAULT 'USER', -- 应用内角色，本期普通用户=USER
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, app)
);

CREATE INDEX idx_user_app_membership_user ON user_app_membership(user_id);

-- 存量准入回填：保证迁移前已能用的用户不被新准入策略挡住。
-- 1) 拥有平台角色(ADMIN/KB_EDITOR/KB_VIEWER)的用户保留 RAGForge 准入，沿用其角色。
INSERT INTO user_app_membership (user_id, app, role, status)
SELECT id, 'ragforge', upper(platform_role), 'ACTIVE'
FROM auth_users
WHERE upper(platform_role) IN ('ADMIN', 'KB_EDITOR', 'KB_VIEWER')
ON CONFLICT (user_id, app) DO NOTHING;

-- 2) 手机号注册过的用户标记 CareerMate 准入。
INSERT INTO user_app_membership (user_id, app, role, status)
SELECT id, 'careermate', 'USER', 'ACTIVE'
FROM auth_users
WHERE phone_hash IS NOT NULL
ON CONFLICT (user_id, app) DO NOTHING;
