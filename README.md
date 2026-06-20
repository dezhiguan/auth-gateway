# Auth Gateway

CareerMate / RAGForge 统一认证网关。项目基于 Spring Boot 3.5 和 Java 21，负责用户登录、短信验证码、密码重置、JWT 签发、refresh token 轮换、OAuth client 认证、token exchange、agent consent、token introspection、JWKS 暴露以及认证事件推送。

## 功能范围

- 用户认证：账号密码登录、手机号验证码登录、密码重置。
- Token 生命周期：Access Token 签发、Refresh Token 轮换、refresh replay 检测、单会话登出、全端登出。
- OAuth 能力：`private_key_jwt` 客户端认证、RFC 8693 token exchange、delegation token、introspection、userinfo。
- Agent 授权：用户创建、查询、撤销 consent，客户端基于 consent 换取 agent delegation token。
- JWT/JWKS：RS256 签名，支持 active/previous key，公开 `/.well-known/jwks.json`。
- 风险控制：登录失败计数、验证码/限流提示、异地登录提示。
- 审计与事件：写入 `audit_logs`，通过 HTTP + HMAC-SHA256 推送 auth event，并落库 `event_outbox`。

## 技术栈

| 项目 | 版本 / 说明 |
|---|---|
| Java | 21+ |
| Spring Boot | 3.5.15 |
| Build | Maven Wrapper |
| Database | PostgreSQL 16，Flyway 自动迁移 |
| Cache / SMS code | dev 默认 memory，prod 使用 Redis |
| JWT | Nimbus JOSE JWT，RS256 |
| SMS | 阿里云 DYPNSAPI，dev 默认 mock code `123456` |
| Container | Docker + k3s |

## 仓库结构

```text
src/main/java/com/careermate/authgw/
  auth/       用户、token、客户端、密码重置等核心认证逻辑
  crypto/     JWT 签名和 JWKS 输出
  events/     auth event outbox、HTTP 投递、订阅安全检查
  oauth/      private_key_jwt、token exchange、consent
  risk/       登录风险控制
  sms/        短信验证码、手机号处理、限流、存储
  web/        REST API Controller
src/main/resources/
  application*.yml
  db/migration/
scripts/      本地密钥生成和协议烟测脚本
deploy/       k3s、Nginx、env、SQL 和发布脚本
docs/         部署文档
```

## 本地运行

### 1. 准备依赖

需要本机安装：

- JDK 21+
- Docker / Docker Compose
- Node.js，用于 `scripts/gen-client-assertion.sh` 和烟测脚本生成 client assertion
- `curl`，可选 `jq`

### 2. 启动 PostgreSQL 和 Redis

```bash
docker-compose up -d postgres redis
```

本地 compose 暴露端口：

- PostgreSQL: `localhost:5433 -> container:5432`
- Redis: `localhost:6380 -> container:6379`

### 3. 生成开发 RSA key

```bash
./scripts/gen-keys.sh
```

生成文件：

```text
config/keys/auth-active.pem
config/keys/auth-previous.pem
```

`config/keys/` 不应提交到 Git。

### 4. 启动服务

如果在宿主机直接运行 Spring Boot，需要覆盖数据库和 Redis 端口：

```bash
AUTH_DB_URL=jdbc:postgresql://localhost:5433/authdb \
AUTH_DB_USERNAME=auth \
AUTH_DB_PASSWORD=auth_dev_password \
SPRING_DATA_REDIS_HOST=localhost \
SPRING_DATA_REDIS_PORT=6380 \
./mvnw spring-boot:run
```

也可以直接通过 compose 启动服务容器：

```bash
docker-compose up -d --build auth-gateway
```

健康检查：

```bash
curl -s http://localhost:8090/actuator/health
curl -s http://localhost:8090/.well-known/jwks.json
```

## 开发默认数据

`dev` profile 下会自动创建一个测试用户：

| 字段 | 值 |
|---|---|
| username | `admin` |
| password | `Admin123!` |
| phone | `13800000000` / `+8613800000000` |
| role | `ADMIN` |

Flyway 默认写入两个 OAuth client：

| client_id | auth_method | allowed_audiences | allowed_scopes |
|---|---|---|---|
| `careermate-backend` | `private_key_jwt` | `careermate-api`, `ragforge-admin-api`, `ragforge-api` | `rag:search` |
| `ragforge-admin-backend` | `private_key_jwt` | `ragforge-admin-api` | `rag:admin:read`, `rag:admin:write` |

dev profile 开启 `auth.dev.allow-local-jwks-client-assertions=true`，本地脚本可以使用 `config/keys/auth-active.pem` 为上述客户端生成 `private_key_jwt` assertion。生产环境必须使用客户端自己的 JWKS URI。

## API 概览

所有需要客户端认证的接口使用以下 form 字段：

| 字段 | 说明 |
|---|---|
| `client_id` | OAuth client id |
| `client_assertion_type` | 固定为 `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | RS256 JWT，`iss/sub=client_id`，`aud=auth.token-endpoint-audience`，`jti` 不可复用，`exp` 最长 10 分钟 |

### 认证与会话

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/auth/login/password` | `application/x-www-form-urlencoded` | 账号密码登录，字段：`account`, `password`, `target_aud` + client assertion |
| `POST` | `/auth/login/mobile` | `application/x-www-form-urlencoded` | 手机验证码登录，字段：`phone`, `code`, `target_aud` + client assertion |
| `POST` | `/auth/token/refresh` | `application/x-www-form-urlencoded` | refresh token 轮换，字段：`refresh_token` + client assertion |
| `POST` | `/auth/logout` | Bearer token | 撤销当前 access token 所在 session |
| `POST` | `/auth/logout-all` | `application/json` + Bearer token | 校验密码后撤销该用户全部 session，body：`{"password":"..."}` |

登录和刷新成功返回：

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### 短信验证码

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/auth/sms/send` | `application/json` | 发送验证码，body：`{"phone":"+8613800000000","scene":"login"}` |

支持的 scene 由 `SmsScene` 解析：

- `login` / `mobile_login`
- `register`
- `reset` / `password_reset`
- `bind_phone`

dev 默认固定验证码为 `123456`。prod profile 使用 Redis 存储验证码并调用阿里云短信。

### 密码重置

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/auth/password/reset/init` | `application/json` | 初始化重置流程，body：`{"account":"..."}` 或带 `phone` |
| `POST` | `/auth/password/reset/verify` | `application/json` | 校验验证码，body：`{"account":"...","code":"123456"}` |
| `POST` | `/auth/password/reset/confirm` | `application/json` | 设置新密码并返回 token，body 包含 `reset_ticket`, `new_password`, `target_aud` + client assertion |

### OAuth / Agent

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/oauth/token-exchange` | `application/x-www-form-urlencoded` | RFC 8693 token exchange |
| `POST` | `/oauth/consents` | `application/json` + Bearer token | 创建 agent consent |
| `GET` | `/oauth/consents` | Bearer token | 查询当前用户 consent |
| `POST` | `/oauth/consents/{id}/revoke` | Bearer token | 撤销 consent |
| `POST` | `/oauth/delegation-token` | `application/x-www-form-urlencoded` | 客户端基于 consent 换取 agent token |
| `POST` | `/oauth/introspect` | `application/x-www-form-urlencoded` | token introspection，字段：`token` + client assertion |
| `GET` | `/userinfo` | Bearer token | 返回当前用户 token 对应用户信息 |

`/oauth/token-exchange` 关键字段：

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_audience=ragforge-api
requested_scopes=rag:search
```

### JWKS / Health / Risk

| Method | Path | 说明 |
|---|---|---|
| `GET` | `/.well-known/jwks.json` | 当前 active/previous 公钥，响应缓存 1 小时 |
| `GET` | `/actuator/health` | Spring Boot health endpoint |
| `POST` | `/risk/login-failure` | 记录登录失败并返回验证码/限流决策 |
| `POST` | `/risk/location-warning` | 返回异地登录提示信息 |

## Token 设计

用户 access token 主要 claims：

- `iss`: `auth.issuer`
- `aud`: 请求的 `target_aud`
- `sub`: `user:<user_id>`
- `principal_type`: `user`
- `user_id`, `tenant_id`, `platform_role`, `rag_role`
- `scopes`
- `session_id`, `session_version`
- `rag_readable_kb_ids`, `rag_writable_kb_ids`

Token 默认 TTL：

| Token | 配置 | 默认 |
|---|---|---:|
| Access Token | `AUTH_ACCESS_TOKEN_TTL_SECONDS` | 900s |
| Refresh Token | `AUTH_REFRESH_TOKEN_TTL_SECONDS` | 604800s |
| Exchange / Delegation Token | `AUTH_EXCHANGE_TOKEN_TTL_SECONDS` | 600s |

Refresh token 每次使用都会轮换。旧 refresh token 被再次使用时，会触发 replay 检测并撤销同一 token family。

## 配置

核心环境变量：

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `SERVER_PORT` | HTTP 端口 | `8090` |
| `SPRING_PROFILES_ACTIVE` | profile，`dev` / `prod` | `dev` |
| `AUTH_DB_URL` | PostgreSQL JDBC URL | `jdbc:postgresql://localhost:5432/authdb` |
| `AUTH_DB_USERNAME` | PostgreSQL 用户 | `auth` |
| `AUTH_DB_PASSWORD` | PostgreSQL 密码 | `auth_dev_password` |
| `SPRING_DATA_REDIS_HOST` | Redis host | Spring Boot 默认 |
| `SPRING_DATA_REDIS_PORT` | Redis port | Spring Boot 默认 |
| `AUTH_ISSUER` | JWT issuer | `https://auth.careermate.cn` |
| `AUTH_TOKEN_ENDPOINT_AUDIENCE` | client assertion `aud` | `https://auth.careermate.cn/oauth/token` |
| `JWKS_ACTIVE_KID` | active key id | `auth-active` |
| `JWKS_ACTIVE_PRIVATE_KEY_PATH` | active 私钥路径 | `config/keys/auth-active.pem` |
| `JWKS_PREVIOUS_KID` | previous key id | `auth-previous`，prod 可为空 |
| `JWKS_PREVIOUS_PRIVATE_KEY_PATH` | previous 私钥路径 | `config/keys/auth-previous.pem`，prod 可为空 |
| `AUTH_SMS_PHONE_HASH_PEPPER` | 手机号、验证码、IP 哈希 pepper | `auth-gateway-dev-pepper` |
| `ALIYUN_SMS_*` | 阿里云短信配置 | 仅 prod 必填 |

生产环境示例见 [deploy/env/auth-gateway.env.example](deploy/env/auth-gateway.env.example)。

## 数据库迁移

Flyway 迁移位于 `src/main/resources/db/migration`，当前包含：

- `auth_users`, `auth_sessions`, `refresh_tokens`
- `oauth_clients`, `agent_consents`
- `sms_codes`, `jti_blacklist`
- `audit_logs`
- `event_subscriptions`, `event_outbox`

手动运行迁移示例：

```bash
./mvnw flyway:migrate \
  -Dflyway.url=jdbc:postgresql://localhost:5433/authdb \
  -Dflyway.user=auth \
  -Dflyway.password=auth_dev_password
```

## Auth Event

当前已知事件类型：

- `session.revoked`
- `user.password.changed`
- `consent.revoked`
- `refresh.replay_detected`

事件推送使用 HTTP POST JSON，Header：

| Header | 说明 |
|---|---|
| `X-Auth-Event-Signature` | `sha256=<hex hmac>`，使用订阅的 `hmac_secret` 对请求 body 做 HMAC-SHA256 |
| `X-Auth-Event-Timestamp` | Unix seconds |

生产环境启用 `event_subscriptions.status='ACTIVE'` 前，必须为每个订阅写入长度至少 16 的真实 `hmac_secret`。`prod` profile 会拒绝空值和 `<TBD...>` 占位符。

## 本地烟测

服务启动后可执行：

```bash
./scripts/test-token-exchange.sh
./scripts/test-refresh-replay.sh
./scripts/e2e-userinfo-introspect.sh
./scripts/test-consent-flow.sh
./scripts/e2e-password-reset.sh
```

如果需要向数据库直接写入测试验证码：

```bash
AUTH_DB_PORT=5433 ./scripts/seed-test-sms-code.sh +8613800000000 123456 reset
```

## 构建与测试

```bash
./mvnw test
./mvnw -DskipTests package
```

CI/CD 定义在 [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml)：

- PR：Semgrep 安全扫描、JDK 21 Maven package、PostgreSQL/Redis 环境下执行测试。
- push `main`：构建 JAR，上传到 Server 3，构建 Docker image，导入 k3s containerd，滚动部署并执行 health/JWKS smoke test。

## 生产部署

生产部署路径是 Server 3 单节点 k3s，详细步骤见 [docs/deployment-auth-gateway.md](docs/deployment-auth-gateway.md)。

关键约束：

- 不要把真实数据库密码、阿里云 AK/SK、HMAC secret、RSA 私钥提交到 Git。
- `/opt/auth-gateway/keys/auth-active.pem` 由宿主机挂载到容器，容器用户为 `10001:10001`。
- `SPRING_PROFILES_ACTIVE=prod` 时短信验证码存储为 Redis，client assertion 禁止使用本地 dev key。
- key rotation 时先配置 previous key，再切换 active key，确保下游 JWKS 缓存过渡。
