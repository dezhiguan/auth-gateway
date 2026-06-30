# Auth Gateway · 统一认证网关

<p align="left">
  <a href="README.md">简体中文</a> ·
  <a href="README.en.md">English</a>
</p>

> CareerMate / RAGForge 多应用统一认证网关。一处签发身份，多应用按准入消费。

[![Java](https://img.shields.io/badge/Java-21-007396?logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.x-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![JWT](https://img.shields.io/badge/JWT-RS256%2FJWKS-000000?logo=jsonwebtokens&logoColor=white)](https://datatracker.ietf.org/doc/html/rfc7519)
[![Deploy](https://img.shields.io/badge/Deploy-k3s%20%2B%20ACR-326CE5?logo=kubernetes&logoColor=white)](docs/deployment-auth-gateway.md)

---

## 概述

Auth Gateway 是 CareerMate 与 RAGForge 共用的统一身份与令牌服务。它把「登录、令牌签发、密钥管理、应用准入、第三方/Agent 授权、认证事件分发」收敛到一个独立服务，下游应用只需信任本网关签发的 JWT 并按 claim 做鉴权，不再各自维护用户体系。

设计上遵循三条原则：

- **身份与准入分离**：`auth_users` 只存身份与凭证；「用户能进哪个 App、以什么角色」由 `user_app_membership` 表达，注册来源不污染身份表。
- **个人化优先**：不再使用租户（tenant）模型，CareerMate 为纯个人化场景，RAGForge 走个人 / 组织 owner 模型。
- **标准协议落地**：客户端认证用 `private_key_jwt`，跨应用换票用 RFC 8693 Token Exchange，公钥经 JWKS 暴露并支持平滑轮换。

## 系统架构

生产部署在单节点 k3s 上，与 CareerMate、RAGForge 应用同集群；数据层（PostgreSQL / Redis）独立部署。

```text
                      公网 auth.careermate.cn
                               │
                    ┌──────────▼───────────┐
                    │  Server 2 入口        │  Nginx 反向代理
                    │  ragforge-nginx       │  (公网入口 / 跳板)
                    └──────────┬───────────┘
                               │  NodePort
                    ┌──────────▼───────────┐
                    │  Server 3 应用层       │  k3s
                    │  Deployment×2 Pod      │  auth-gateway:8090
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Server 1 数据层       │  PostgreSQL authdb
                    │  (内网)                │  Redis
                    └──────────────────────┘

   认证事件 (HTTP + HMAC-SHA256) ──► RAGForge / CareerMate 订阅端
```

| 层 | 节点 | 组件 |
|---|---|---|
| Server 1 数据层 | 内网节点 | PostgreSQL `authdb`、Redis |
| Server 2 入口层 | 公网入口 / 跳板 | Nginx 公网入口 `auth.careermate.cn` |
| Server 3 应用层 | 内网节点 | k3s `auth-gateway` Deployment，集群内 NodePort |

> 具体内网地址、NodePort、跳板机等基础设施细节见私有部署文档,不在公开仓库中披露。详细部署步骤见 [docs/deployment-auth-gateway.md](docs/deployment-auth-gateway.md)。

## 核心能力

| 领域 | 能力 |
|---|---|
| **用户认证** | 账号密码登录（账号可为用户名 / 手机号 / 邮箱）、手机验证码登录、密码重置 |
| **注册与补全** | 手机号为关联键的注册 / 账号补全；已存在手机号自动关联并回填资料 |
| **凭证管理** | 登录态下设置密码、绑定邮箱、设置用户名（用户名支持中文，2–32 位）|
| **令牌生命周期** | Access Token 签发、Refresh Token 轮换、refresh replay 检测与 token family 撤销、单会话登出、全端登出 |
| **OAuth 能力** | `private_key_jwt` 客户端认证、RFC 8693 Token Exchange、delegation token、introspection、userinfo |
| **Agent 授权** | 用户创建 / 查询 / 撤销 consent，客户端凭 consent 换取 agent delegation token |
| **应用准入** | `user_app_membership` 决定用户可进入的 App 与应用内角色（`careermate` / `ragforge`）|
| **JWT / JWKS** | RS256 签名，active / previous 双密钥，公开 `/.well-known/jwks.json`，支持平滑轮换 |
| **风险控制** | 登录失败计数与锁定、验证码 / 限流提示、异地登录提示 |
| **审计与事件** | 写入 `audit_logs`；通过 HTTP + HMAC-SHA256 推送认证事件并落 `event_outbox` |
| **内部接口** | 按手机号精确解析用户（供下游邀请成员，仅授权 client 可调用，防枚举）|

## 技术栈

| 项目 | 版本 / 说明 |
|---|---|
| Java | 21（Maven Enforcer 强制 ≥21）|
| Spring Boot | 3.5.x（`spring-boot-starter-web` / `jdbc` / `data-redis` / `actuator`）|
| 构建 | Maven Wrapper |
| 数据库 | PostgreSQL 16，Flyway 启动时自动迁移 |
| 验证码存储 | dev 默认内存，prod 使用 Redis |
| JWT | Nimbus JOSE + JWT，RS256 |
| 短信 | 阿里云号码认证服务（DYPNSAPI），dev 默认 mock code `123456` |
| 容器 / 编排 | Docker（`eclipse-temurin:21-jre-jammy`）+ k3s |
| 镜像仓库 | 阿里云容器镜像服务（ACR），镜像 tag 编码 commit `auth-<sha12>` |

## 仓库结构

```text
src/main/java/com/careermate/authgw/
  auth/       身份、令牌、凭证、注册、登录、应用准入(membership)
  audit/      审计日志
  crypto/     JWT 签名与 JWKS 输出
  events/     认证事件 outbox、HTTP 投递、订阅安全校验
  oauth/      private_key_jwt、token exchange、consent
  risk/       登录风险控制
  sms/        验证码、手机号处理、限流、存储
  web/        REST API Controller
src/main/resources/
  application*.yml
  db/migration/        Flyway 迁移 V1–V9
scripts/      本地密钥生成与协议烟测脚本
deploy/       k3s 清单、Nginx、env、SQL、发布脚本
docs/         部署文档
```

## 快速开始（本地）

### 1. 依赖

- JDK 21+
- Docker / Docker Compose
- Node.js（用于生成 `private_key_jwt` 的烟测脚本）
- `curl`，可选 `jq`

### 2. 启动 PostgreSQL 与 Redis

```bash
docker-compose up -d postgres redis
```

本地端口映射：

- PostgreSQL：`localhost:5433 -> 容器:5432`
- Redis：`localhost:6380 -> 容器:6379`

### 3. 生成开发 RSA 密钥

```bash
./scripts/gen-keys.sh
# 生成 config/keys/auth-active.pem 与 config/keys/auth-previous.pem
```

`config/keys/` 不提交到 Git。

### 4. 启动服务

宿主机直接运行 Spring Boot（覆盖数据库 / Redis 端口）：

```bash
AUTH_DB_URL=jdbc:postgresql://localhost:5433/authdb \
AUTH_DB_USERNAME=auth \
AUTH_DB_PASSWORD=auth_dev_password \
SPRING_DATA_REDIS_HOST=localhost \
SPRING_DATA_REDIS_PORT=6380 \
./mvnw spring-boot:run
```

或直接用 compose 构建并启动服务容器：

```bash
docker-compose up -d --build auth-gateway
```

健康检查：

```bash
curl -s http://localhost:8090/actuator/health
curl -s http://localhost:8090/.well-known/jwks.json
```

## 开发默认数据

`dev` profile 启动时自动播种一个测试用户，并为其授予两个 App 的准入：

| 字段 | 值 |
|---|---|
| username | `admin` |
| password | `Admin123!` |
| phone | `13800000000` / `+8613800000000` |
| platform_role | `ADMIN` |
| membership | `ragforge`(ADMIN) + `careermate`(USER) |

Flyway 默认写入两个 OAuth client：

| client_id | auth_method | allowed_audiences | allowed_scopes |
|---|---|---|---|
| `careermate-backend` | `private_key_jwt` | `careermate-api`, `ragforge-admin-api`, `ragforge-api` | `rag:search` |
| `ragforge-admin-backend` | `private_key_jwt` | `ragforge-admin-api` | `rag:admin:read`, `rag:admin:write` |

`dev` profile 开启 `auth.dev.allow-local-jwks-client-assertions=true`，本地脚本可用 `config/keys/auth-active.pem` 为上述 client 生成 `private_key_jwt` assertion。生产环境必须使用客户端自有的 JWKS URI。

## API 概览

需要客户端认证的接口统一使用以下字段（`private_key_jwt`）：

| 字段 | 说明 |
|---|---|
| `client_id` | OAuth client id |
| `client_assertion_type` | 固定为 `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | RS256 JWT，`iss/sub=client_id`，`aud=AUTH_TOKEN_ENDPOINT_AUDIENCE`，`jti` 不可复用，`exp` 最长 10 分钟 |

### 认证与会话

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/auth/login/password` | `x-www-form-urlencoded` | 账号密码登录，`account`（用户名/手机号/邮箱）, `password`, `target_aud` + client assertion |
| `POST` | `/auth/login/mobile` | `x-www-form-urlencoded` | 手机验证码登录，`phone`, `code`, `target_aud` + client assertion（号码未注册时自动建号）|
| `POST` | `/auth/token/refresh` | `x-www-form-urlencoded` | refresh token 轮换，`refresh_token` + client assertion |
| `POST` | `/auth/logout` | Bearer token | 撤销当前 access token 所在 session（携带 jti 供订阅端吊销）|
| `POST` | `/auth/logout-all` | `json` + Bearer token | 校验密码后撤销该用户全部 session，body：`{"password":"..."}` |

登录 / 刷新成功返回：

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 900 }
```

### 注册与凭证

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/auth/register` | `json` | 注册 / 账号补全，body：`{"phone","smsCode","username","email","password","app"}`；`app ∈ {careermate, ragforge}`；手机号已存在则关联回填 |
| `POST` | `/auth/credential/set-password` | `json` + Bearer | 设置 / 修改密码，body：`{"oldPassword","newPassword"}` |
| `POST` | `/auth/credential/bind-email` | `json` + Bearer | 绑定邮箱，body：`{"email","password"}` |
| `POST` | `/auth/credential/set-username` | `json` + Bearer | 设置用户名（中文，2–32 位），body：`{"username"}` |

注册返回示例：

```json
{ "userId": 1001, "linked": false, "message": "注册成功" }
```

### 短信验证码

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/auth/sms/send` | `json` | 发送验证码，body：`{"phone":"+8613800000000","scene":"login"}` |

`scene` 取值（由 `SmsScene` 解析）：`login` / `mobile_login`、`register`、`reset` / `password_reset`、`bind_phone`。dev 固定验证码 `123456`；prod 使用 Redis 存储并调用阿里云短信。

### 密码重置

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/auth/password/reset/init` | `json` | 初始化重置，body：`{"account"}` 或带 `phone` |
| `POST` | `/auth/password/reset/verify` | `json` | 校验验证码，body：`{"account","code"}` |
| `POST` | `/auth/password/reset/confirm` | `json` | 设新密码并返回 token，body：`reset_ticket`, `new_password`, `target_aud` + client assertion |

### OAuth / Agent

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/oauth/token-exchange` | `x-www-form-urlencoded` | RFC 8693 token exchange |
| `POST` | `/oauth/consents` | `json` + Bearer | 创建 agent consent |
| `GET` | `/oauth/consents` | Bearer | 查询当前用户 consent |
| `POST` | `/oauth/consents/{id}/revoke` | Bearer | 撤销 consent |
| `POST` | `/oauth/delegation-token` | `x-www-form-urlencoded` | 客户端凭 consent 换取 agent token |
| `POST` | `/oauth/introspect` | `x-www-form-urlencoded` | token introspection，`token` + client assertion |
| `GET` | `/userinfo` | Bearer | 返回当前 token 对应用户信息 |

`/oauth/token-exchange` 关键字段：

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_audience=ragforge-api
requested_scopes=rag:search
```

### 内部接口

| Method | Path | Content-Type | 说明 |
|---|---|---|---|
| `POST` | `/internal/users/resolve-by-phone` | `x-www-form-urlencoded` | 按手机号精确解析用户（供下游邀请成员）。仅授权 client 可调用，仅做哈希精确匹配、返回脱敏号码，不分页、不模糊搜索 |

### JWKS / Health / Risk

| Method | Path | 说明 |
|---|---|---|
| `GET` | `/.well-known/jwks.json` | active / previous 公钥，响应缓存 1 小时 |
| `GET` | `/actuator/health` | Spring Boot health endpoint |
| `POST` | `/risk/login-failure` | 记录登录失败并返回验证码 / 限流决策 |
| `POST` | `/risk/location-warning` | 返回异地登录提示 |

## Token 设计

用户 access token 主要 claims：

- `iss`：`auth.issuer`
- `aud`：请求的 `target_aud`
- `sub`：`user:<user_id>`
- `principal_type`：`user`
- `user_id`、`platform_role`、`rag_role`
- `scopes`（按 `target_aud` 与角色派生）
- `session_id`、`session_version`
- `rag_readable_kb_ids`、`rag_writable_kb_ids`

> 注：`tenant_id` 已在 V9 迁移中移除，令牌不再携带租户维度。

Token 默认 TTL：

| Token | 配置 | 默认 |
|---|---|---:|
| Access Token | `AUTH_ACCESS_TOKEN_TTL_SECONDS` | 900s |
| Refresh Token | `AUTH_REFRESH_TOKEN_TTL_SECONDS` | 604800s |
| Exchange / Delegation Token | `AUTH_EXCHANGE_TOKEN_TTL_SECONDS` | 600s |

Refresh token 每次使用即轮换；旧 token 被再次使用会触发 replay 检测并撤销同一 token family。

## 配置

核心环境变量：

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `SERVER_PORT` | HTTP 端口 | `8090` |
| `SPRING_PROFILES_ACTIVE` | profile（`dev` / `prod`）| `dev` |
| `AUTH_DB_URL` | PostgreSQL JDBC URL | `jdbc:postgresql://localhost:5432/authdb` |
| `AUTH_DB_USERNAME` / `AUTH_DB_PASSWORD` | 数据库账号 | `auth` / `auth_dev_password` |
| `SPRING_DATA_REDIS_HOST` / `SPRING_DATA_REDIS_PORT` | Redis 连接 | Spring Boot 默认 |
| `AUTH_ISSUER` | JWT issuer | `https://auth.careermate.cn` |
| `AUTH_TOKEN_ENDPOINT_AUDIENCE` | client assertion `aud` | `https://auth.careermate.cn/oauth/token` |
| `JWKS_ACTIVE_KID` / `JWKS_ACTIVE_PRIVATE_KEY_PATH` | active 密钥 | `auth-active` / `config/keys/auth-active.pem` |
| `JWKS_PREVIOUS_KID` / `JWKS_PREVIOUS_PRIVATE_KEY_PATH` | previous 密钥（prod 可为空）| `auth-previous` / `config/keys/auth-previous.pem` |
| `AUTH_SMS_PHONE_HASH_PEPPER` | 手机号 / 验证码 / IP 哈希 pepper | `auth-gateway-dev-pepper` |
| `AUTH_RAGFORGE_EVENT_*` / `AUTH_CAREERMATE_EVENT_*` | 事件订阅 endpoint 与 HMAC 密钥 | 仅 prod 必填 |
| `ALIYUN_SMS_*` | 阿里云短信配置 | 仅 prod 必填 |

生产示例见 [deploy/env/auth-gateway.env.example](deploy/env/auth-gateway.env.example)。

## 数据库迁移

Flyway 迁移位于 `src/main/resources/db/migration`（V1–V9）：

| 版本 | 内容 |
|---|---|
| V1 | `auth_users`、`auth_sessions`、`refresh_tokens`、`oauth_clients`、`agent_consents`、`sms_codes`、`jti_blacklist` |
| V2–V3 | 播种 OAuth client + `allowed_scopes` |
| V4 | `audit_logs` |
| V5 | 事件 HTTP 推送（`event_subscriptions`、`event_outbox`）|
| V6 | session audience（历史含 tenant，已于 V9 回退）|
| V7 | 播种 `event_subscriptions` |
| V8 | 账号标识部分唯一索引 + 应用准入表 `user_app_membership`（含存量回填）|
| V9 | 移除 `auth_users.tenant_id`（去租户模型）|

手动迁移示例：

```bash
./mvnw flyway:migrate \
  -Dflyway.url=jdbc:postgresql://localhost:5433/authdb \
  -Dflyway.user=auth -Dflyway.password=auth_dev_password
```

## 认证事件

当前事件类型：`session.revoked`、`user.password.changed`、`consent.revoked`、`refresh.replay_detected`。

投递为 HTTP POST JSON，请求头：

| Header | 说明 |
|---|---|
| `X-Auth-Event-Signature` | `sha256=<hex hmac>`，用订阅的 `hmac_secret` 对请求 body 做 HMAC-SHA256 |
| `X-Auth-Event-Timestamp` | Unix seconds |

生产启用 `event_subscriptions.status='ACTIVE'` 前，每个订阅必须写入长度 ≥16 的真实 `hmac_secret`；`prod` profile 会拒绝空值与 `<TBD...>` 占位符。

## 本地烟测

服务启动后可执行：

```bash
./scripts/test-token-exchange.sh
./scripts/test-refresh-replay.sh
./scripts/e2e-userinfo-introspect.sh
./scripts/test-consent-flow.sh
./scripts/e2e-password-reset.sh
```

向数据库直接写入测试验证码：

```bash
AUTH_DB_PORT=5433 ./scripts/seed-test-sms-code.sh +8613800000000 123456 reset
```

## 构建与测试

```bash
./mvnw test
./mvnw -DskipTests package
```

## CI/CD

流水线定义在 [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml)：

**Pull Request**

1. Semgrep 安全扫描（OWASP Top Ten + secrets）。
2. JDK 21 Maven `package`。
3. 在 PostgreSQL 16 / Redis 7 服务下执行单元测试。

**Push `main`**

1. 构建并测试。
2. 在 GitHub Actions 内构建 Docker 镜像并**推送到阿里云 ACR**（tag `auth-<sha12>`）。
3. 经 Server 2 跳板 SSH 上传 JAR、Dockerfile、脚本、k8s 清单到 Server 3。
4. Server 3 从 ACR 拉取镜像（配置 `acr-pull-secret`），刷新 `auth-gateway-env` Secret，应用 namespace / service / deployment，滚动 2 个 Pod。
5. Smoke 检查 `/actuator/health` 与 `/.well-known/jwks.json`。

> 历史的「Server 3 本地构建镜像并 import 到 k3s containerd」路径仍作为离线回退保留（`deploy-from-github.sh` 的 `USE_REMOTE_IMAGE=0` 分支），生产默认走 ACR 拉取。

## 生产部署

生产路径为 Server 3 单节点 k3s，完整步骤见 [docs/deployment-auth-gateway.md](docs/deployment-auth-gateway.md)。关键约束：

- 真实数据库密码、阿里云 AK/SK、HMAC secret、RSA 私钥**禁止**提交到 Git。
- `/opt/auth-gateway/keys/auth-active.pem` 由宿主机挂载到容器，容器用户 `10001:10001`，密钥目录 `700`、私钥 `640`。
- `SPRING_PROFILES_ACTIVE=prod` 时验证码存 Redis，且禁止使用本地 dev key 签 client assertion。
- 密钥轮换：先配置 previous key，再切换 active key，确保下游 JWKS 缓存平滑过渡。

## 许可

内部项目，未附带开源许可证。如需对外分发请先与维护者确认。
