-- 记住我(remember)：refresh token 生命周期改为会话级属性，跨旋转继承（滑动窗口）。
-- NULL 表示沿用默认 TTL(auth.refresh-token-ttl-seconds)，历史会话无需回填。
ALTER TABLE auth_sessions ADD COLUMN refresh_ttl_seconds BIGINT;
