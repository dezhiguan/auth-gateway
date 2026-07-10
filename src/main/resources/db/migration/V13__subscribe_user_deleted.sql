-- 让 ragforge 订阅 user.deleted 事件（账号注销冷静期到期后，rag-forge 需清理自己的 api_keys/org_members/user_profile）。
-- 幂等：仅当数组未包含时追加。
UPDATE event_subscriptions
SET event_types = event_types || '["user.deleted"]'::jsonb
WHERE subscriber = 'ragforge'
  AND NOT jsonb_exists(event_types, 'user.deleted');
