# 事件吊销 webhook —— HMAC 密钥与订阅配置

"登出 / 改密 → webhook → 下游访问令牌吊销"链路依赖网关把事件投递到 RAGForge / CareerMate，并以 HMAC-SHA256 签名。`deployment.yaml` 通过 `envFrom: secretRef: authgw-event-hmac` 注入订阅配置，`EventSubscriptionBootstrap` 启动时据此激活 `authdb.event_subscriptions`。

**密钥值不入 git**。三个仓库的下游 secret 与本 secret 必须用 **同一把强随机密钥**，否则下游验签 401。

## 创建 secret（一次性，prod）

```bash
# 一把强密钥，三处共用
S=$(openssl rand -hex 32)

# 1) 网关：订阅 endpoint + 密钥（EventSubscriptionBootstrap 读取）
kubectl -n auth-gateway create secret generic authgw-event-hmac \
  --from-literal=AUTH_EVENTS_SUBSCRIPTIONS_RAGFORGE_ENDPOINT=http://ragforge-backend.ragforge.svc.cluster.local:8080/api/v1/events/session-revoked \
  --from-literal=AUTH_EVENTS_SUBSCRIPTIONS_RAGFORGE_HMAC_SECRET="$S" \
  --from-literal=AUTH_EVENTS_SUBSCRIPTIONS_CAREERMATE_ENDPOINT=http://careermate-backend.careermate.svc.cluster.local:18080/api/v1/events/session-revoked \
  --from-literal=AUTH_EVENTS_SUBSCRIPTIONS_CAREERMATE_HMAC_SECRET="$S"

# 2) RAGForge 下游验签密钥（rag-forge 仓库 deploy 引用）
kubectl -n ragforge create secret generic ragforge-event-hmac \
  --from-literal=RAGFORGE_AUTH_EVENT_HMAC_SECRET="$S"

# 3) CareerMate 下游验签密钥（careermate 仓库 deploy 引用）
kubectl -n careermate create secret generic careermate-event-hmac \
  --from-literal=AUTH_EVENT_HMAC_SECRET="$S"
```

## 验证

```bash
# 订阅应为 ACTIVE + 集群内 endpoint + 有密钥
psql "$AUTHDB" -c "SELECT subscriber,status,endpoint_url,(hmac_secret<>'') FROM event_subscriptions"
# 网关启动日志应见：EventSubscriptionBootstrap : auth event subscription activated; subscriber=...
# 端到端：改密后旧 access token 调下游 /api/v1/me 应 401
```

> 注意：`event_subscriptions` 表行由网关 `EventSubscriptionBootstrap`（@PostConstruct）按上面 endpoint env 维护；endpoint 为空则跳过不写。`DevAuthDataSeeder` 仅 `@Profile("dev")`，prod 不参与。
