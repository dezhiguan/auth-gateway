-- 让 ragforge 订阅 user.app_removed 事件：应用级注销冷静期到期后，网关发该事件，
-- rag-forge 收到(app=ragforge)后清理本地个人数据（org_members / api_keys / user_profile）。
-- 幂等：仅当数组未包含时追加。
UPDATE event_subscriptions
SET event_types = event_types || '["user.app_removed"]'::jsonb
WHERE subscriber = 'ragforge'
  AND NOT jsonb_exists(event_types, 'user.app_removed');
