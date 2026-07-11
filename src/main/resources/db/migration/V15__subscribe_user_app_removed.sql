-- 让 careermate 订阅 user.app_removed 事件：应用级注销冷静期到期后，网关发该事件，
-- careermate 收到(app=careermate)后清理本地个人数据（user 主记录匿名化 + 简历/对话等）。
-- 幂等：仅当数组未包含时追加。
UPDATE event_subscriptions
SET event_types = event_types || '["user.app_removed"]'::jsonb
WHERE subscriber = 'careermate'
  AND NOT jsonb_exists(event_types, 'user.app_removed');
