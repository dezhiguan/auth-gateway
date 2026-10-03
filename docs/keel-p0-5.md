# Keel P0-5 对接约定

## 客户端开通

`POST /internal/clients` 和 `DELETE /internal/clients/{client_id}` 只由 Keel 内网调用。公网 Nginx 配置拒绝 `/internal/clients`，Kubernetes NodePort 以 `externalTrafficPolicy: Local` 保留来源 IP，服务端也拒绝来自非内网地址的直连请求。`AUTH_INTERNAL_PROVISIONER_CLIENT_ID` 必须设置为已预先配置的 Keel provisioner 客户端 ID；未设置时接口关闭。该客户端使用现有 `private_key_jwt` 鉴权，公钥从其 `jwks_uri` 获取。引导这一个 provisioner 客户端需要运维先在 `oauth_clients` 创建记录，不通过本接口自举。

引导记录示例（替换为 Keel-server 实际可达的 JWKS 地址）：

```sql
INSERT INTO oauth_clients(client_id, client_name, auth_method, jwks_uri,
                          allowed_grant_types, allowed_audiences, allowed_scopes, status)
VALUES ('keel-server-provisioner', 'Keel Server Provisioner', 'private_key_jwt',
        'https://keel.example/agents/keel-server-provisioner/jwks.json',
        '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 'ACTIVE');
```

随后将 `AUTH_INTERNAL_PROVISIONER_CLIENT_ID=keel-server-provisioner` 配置到 auth-gateway，并确保该客户端的私钥只由 Keel-server 持有。首次注册 `keel-gateway` 时也使用此接口，`allowed_audiences` 包含 `keel-api` 和可调用智能体受众。

请求头：`X-Client-Id`、`X-Client-Assertion-Type`（`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`）、`X-Client-Assertion`。断言的 `aud` 仍按现有配置 `AUTH_TOKEN_ENDPOINT_AUDIENCE`，有效期、jti 防重放仍由 `ClientAuthenticator` 校验。重复操作必须使用新断言，因为 jti 不可重放。

请求体示例：

```json
{
  "client_id": "ops-copilot",
  "jwks_uri": "https://keel.example/agents/ops-copilot/jwks.json",
  "allowed_audiences": ["keel-api", "ops-copilot", "askdb"],
  "scopes": ["agent:invoke"],
  "grant_types": ["token-exchange"]
}
```

`POST` 对 Keel 托管的 `client_id` 执行 upsert，覆盖其 `jwks_uri`、受众、scopes 和授权类型；现有 CareerMate/RAGForge 客户端不允许覆盖。`DELETE` 只删除 Keel 托管的客户端，重复删除返回 204。该操作不能删除引导用的 provisioner 客户端。两种操作都在同一事务中写审计；客户端断言的 jti 防重放记录在该事务外写入，即使注册失败也不能重用断言。

`allowed_audiences` 是 OAuth 客户端的一组完整受众白名单，存于 `oauth_clients.allowed_audiences`。Keel-server 每次注册或修改 manifest 的 `delegates` 时重新生成整组并调用 `POST`：智能体客户端包含自身受众、所有被委派智能体受众，以及需要访问的共享服务受众；从 `delegates` 删除的受众也必须从该组删除。keel-gateway 客户端包含 `keel-api` 和可调用的所有智能体受众。换票时源 token 的 aud 和目标 aud 都须属于这组。`audience_scopes` 是另一张表，定义用户登录某个 aud 时可持有的 scopes；Keel-server 不写它，后续新增登录 scopes 需要数据库迁移。

## 用户 token

现有 `careermate-backend` 客户端现可申请 `target_aud=keel-api`，得到 `aud=keel-api` 的用户 token。原有 `careermate-api`、`ragforge-admin-api` 登录受众保持原样。`audience_scopes` 迁移保留原有 scope 规则，并为 `keel-api` 签发 `agent:invoke` 和 `rag:search`。`user_roles` 表按 `(user_id, role)` 存业务角色；用户登录和刷新时读表签发多值 `roles` claim，换票时沿用源 token 中的角色。老 token 没有 `roles` 时视为空集合；后续准入过滤器需要同样处理，不能默许有角色要求的智能体。

## 现有 consent / delegation 行为核实

`POST /oauth/consents` 以活跃用户 access token 创建 consent，授权粒度是 **用户 + 客户端主体 + scopes + 可访问 KB ID + 过期时间**，没有目标智能体 aud，也没有单次流程 ID。`GET /oauth/consents` 列出该用户记录；`POST /oauth/consents/{id}/revoke` 撤销。`POST /oauth/delegation-token` 使用客户端 `private_key_jwt`、`consent_id`、`requested_audience`、`requested_scopes` 签发 600 秒的 `principal_type=agent` token；要求 consent 未过期/撤销、客户端匹配、目标 aud 在客户端白名单、scopes 同时在客户端与 consent 白名单。签发时读取用户的当前 `session_version`，但当前代码没有检查用户状态是否 `ACTIVE`，也没有把 consent 限定到特定目标 aud 或单次流程。P3-1 若需要按流程或目标限制，必须另行设计；现状不能当成已有该粒度的授权。

## 本地验证（2026-10-03）

使用本机 PostgreSQL 18 的 `authdb` 克隆库 `authdb_p05_codex` 验证；原 `authdb` 保持在 V16，未改动。测试时实例分别使用 18090 和 18091 端口。后一个实例关闭开发环境本地公钥快捷验签，通过客户端的 `jwks_uri` 获取公钥。验证后已关闭实例并删除克隆库。

| 检查 | 结果 |
|---|---|
| auth-gateway `./mvnw test` | 197 项通过 |
| Flyway V17 | 克隆库迁移到 V17，Spring 启动时验证 17 个迁移成功 |
| 真实 HTTP 登录、刷新、userinfo | `aud=keel-api`，`roles=[ops_engineer]`，scopes 包含 `agent:invoke` 与 `rag:search`；刷新保留角色 |
| 客户端注册与换票 | 注册/重复注册 200，`ops-copilot` 换票 200，目标受众不在白名单时 403；删除/重复删除 204 |
| 客户端隔离与断言重放 | 覆盖非 Keel 客户端 409，失败请求的同一断言重试 401；不可用的 `jwks_uri` 在关闭快捷验签的实例上返回 401 |
| RAGForge `AuthGatewayProxyClientTest,ClientAssertionFactoryTest` | 17 项通过 |
| CareerMate `AuthGatewayClientTest,RagForgeClientTest,AuthMeJwtTest,MobileUserWebLoginTest,JwtAuthenticationFilterEventRevocationTest` | 26 项通过；`AuthMeJwtTest` 使用独立的 `careermate_test_db` |

现有 `scripts/test-token-exchange.sh` 对 CareerMate 登录、缺客户端断言、受众拒绝和成功换票的检查也全部通过。公网入口 404 由 Nginx 配置实现；本机没有对应公网入口，部署后仍需验证实际入口返回 404。测试克隆库中的 provisioner、业务角色和审计记录仅用于本次验证；正式环境仍需按上文引导 provisioner 并由业务系统维护 `user_roles`。
