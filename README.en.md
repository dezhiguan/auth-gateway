# Auth Gateway · Unified Authentication Gateway

<p align="left">
  <a href="README.md">简体中文</a> ·
  <a href="README.en.md">English</a>
</p>

> Unified authentication gateway shared by CareerMate and RAGForge. Issue identity once, consume across apps by admission.

[![Java](https://img.shields.io/badge/Java-21-007396?logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.x-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![JWT](https://img.shields.io/badge/JWT-RS256%2FJWKS-000000?logo=jsonwebtokens&logoColor=white)](https://datatracker.ietf.org/doc/html/rfc7519)
[![Deploy](https://img.shields.io/badge/Deploy-k3s%20%2B%20ACR-326CE5?logo=kubernetes&logoColor=white)](docs/deployment-auth-gateway.md)

---

## Overview

Auth Gateway is the shared identity and token service for CareerMate and RAGForge. It consolidates login, token issuance, key management, application admission, third-party / agent authorization, and authentication-event delivery into a single service. Downstream apps simply trust the JWTs it signs and authorize on claims — they no longer maintain their own user systems.

Three design principles:

- **Identity separated from admission**: `auth_users` holds only identity and credentials; "which app a user may enter and with what role" is expressed by `user_app_membership`, so registration source never pollutes the identity table.
- **Personal-first**: the tenant model is dropped. CareerMate is a purely personal experience; RAGForge uses a personal / organization owner model.
- **Standards-based**: client authentication uses `private_key_jwt`, cross-app token swap uses RFC 8693 Token Exchange, and public keys are exposed via JWKS with smooth rotation.

## Architecture

Production runs on a single-node k3s cluster alongside the CareerMate and RAGForge app services. The data tier (PostgreSQL / Redis) is deployed separately.

```text
                    Public  auth.careermate.cn
                               │
                    ┌──────────▼───────────┐
                    │  Server 2 Ingress     │  Nginx reverse proxy
                    │  ragforge-nginx       │  (public entry / jump)
                    └──────────┬───────────┘
                               │  NodePort 31091
                    ┌──────────▼───────────┐
                    │  Server 3 App tier    │  k3s
                    │  Deployment ×2 Pods   │  auth-gateway:8090
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Server 1 Data tier   │  PostgreSQL authdb
                    │  172.25.90.183        │  Redis
                    └──────────────────────┘

   Auth events (HTTP + HMAC-SHA256) ──► RAGForge / CareerMate subscribers
```

| Tier | Private IP | Components |
|---|---|---|
| Server 1 Data | `172.25.90.183` | PostgreSQL `authdb`, Redis |
| Server 2 Ingress | `172.19.40.32` (public jump `8.163.63.222`) | Nginx public entry `auth.careermate.cn` |
| Server 3 App | `172.25.90.184` | k3s `auth-gateway` Deployment, NodePort `31091` |

See [docs/deployment-auth-gateway.md](docs/deployment-auth-gateway.md) for the full deployment guide.

## Capabilities

| Area | Capability |
|---|---|
| **User auth** | Password login (account = username / phone / email), SMS-code login, password reset |
| **Register & complete** | Phone-keyed registration / account completion; an existing phone auto-links and backfills profile |
| **Credential mgmt** | Set password, bind email, set username while logged in (username allows CJK, 2–32 chars) |
| **Token lifecycle** | Access token issuance, refresh-token rotation, refresh replay detection with token-family revocation, single-session logout, logout-all |
| **OAuth** | `private_key_jwt` client auth, RFC 8693 Token Exchange, delegation token, introspection, userinfo |
| **Agent authorization** | Users create / list / revoke consent; clients exchange a consent for an agent delegation token |
| **App admission** | `user_app_membership` decides which apps a user may enter and the in-app role (`careermate` / `ragforge`) |
| **JWT / JWKS** | RS256 signing, active / previous dual keys, public `/.well-known/jwks.json`, smooth rotation |
| **Risk control** | Login-failure counting and lockout, captcha / rate-limit hints, off-site login warnings |
| **Audit & events** | Writes `audit_logs`; delivers auth events over HTTP + HMAC-SHA256 with an `event_outbox` |
| **Internal API** | Exact resolve-by-phone (for downstream member invites; authorized clients only, anti-enumeration) |

## Tech Stack

| Item | Version / Notes |
|---|---|
| Java | 21 (Maven Enforcer requires ≥21) |
| Spring Boot | 3.5.x (`web` / `jdbc` / `data-redis` / `actuator`) |
| Build | Maven Wrapper |
| Database | PostgreSQL 16, Flyway auto-migrate on startup |
| Code store | In-memory in dev, Redis in prod |
| JWT | Nimbus JOSE + JWT, RS256 |
| SMS | Aliyun Number Verification (DYPNSAPI); dev mock code `123456` |
| Container / orchestration | Docker (`eclipse-temurin:21-jre-jammy`) + k3s |
| Image registry | Aliyun ACR; image tag encodes commit `auth-<sha12>` |

## Repository Layout

```text
src/main/java/com/careermate/authgw/
  auth/       identity, tokens, credentials, registration, login, app membership
  audit/      audit logging
  crypto/     JWT signing and JWKS output
  events/     auth-event outbox, HTTP delivery, subscription guards
  oauth/      private_key_jwt, token exchange, consent
  risk/       login risk control
  sms/        verification codes, phone handling, rate limiting, storage
  web/        REST controllers
src/main/resources/
  application*.yml
  db/migration/        Flyway migrations V1–V9
scripts/      local key generation and protocol smoke tests
deploy/       k3s manifests, Nginx, env, SQL, release scripts
docs/         deployment docs
```

## Quick Start (local)

### 1. Prerequisites

- JDK 21+
- Docker / Docker Compose
- Node.js (used by the `private_key_jwt` smoke scripts)
- `curl`, optionally `jq`

### 2. Start PostgreSQL and Redis

```bash
docker-compose up -d postgres redis
```

Local port mapping:

- PostgreSQL: `localhost:5433 -> container:5432`
- Redis: `localhost:6380 -> container:6379`

### 3. Generate dev RSA keys

```bash
./scripts/gen-keys.sh
# creates config/keys/auth-active.pem and config/keys/auth-previous.pem
```

`config/keys/` is not committed to Git.

### 4. Run the service

Run Spring Boot directly on the host (override DB / Redis ports):

```bash
AUTH_DB_URL=jdbc:postgresql://localhost:5433/authdb \
AUTH_DB_USERNAME=auth \
AUTH_DB_PASSWORD=auth_dev_password \
SPRING_DATA_REDIS_HOST=localhost \
SPRING_DATA_REDIS_PORT=6380 \
./mvnw spring-boot:run
```

Or build and run the service container via compose:

```bash
docker-compose up -d --build auth-gateway
```

Health checks:

```bash
curl -s http://localhost:8090/actuator/health
curl -s http://localhost:8090/.well-known/jwks.json
```

## Dev Seed Data

The `dev` profile seeds a test user and grants it admission to both apps:

| Field | Value |
|---|---|
| username | `admin` |
| password | `Admin123!` |
| phone | `13800000000` / `+8613800000000` |
| platform_role | `ADMIN` |
| membership | `ragforge`(ADMIN) + `careermate`(USER) |

Flyway seeds two OAuth clients:

| client_id | auth_method | allowed_audiences | allowed_scopes |
|---|---|---|---|
| `careermate-backend` | `private_key_jwt` | `careermate-api`, `ragforge-admin-api`, `ragforge-api` | `rag:search` |
| `ragforge-admin-backend` | `private_key_jwt` | `ragforge-admin-api` | `rag:admin:read`, `rag:admin:write` |

The `dev` profile enables `auth.dev.allow-local-jwks-client-assertions=true`, so local scripts can sign `private_key_jwt` assertions with `config/keys/auth-active.pem`. Production must use each client's own JWKS URI.

## API Overview

Endpoints requiring client authentication use `private_key_jwt` fields:

| Field | Description |
|---|---|
| `client_id` | OAuth client id |
| `client_assertion_type` | fixed `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | RS256 JWT, `iss/sub=client_id`, `aud=AUTH_TOKEN_ENDPOINT_AUDIENCE`, unique `jti`, `exp` ≤ 10 min |

### Auth & Sessions

| Method | Path | Content-Type | Description |
|---|---|---|---|
| `POST` | `/auth/login/password` | `x-www-form-urlencoded` | Password login: `account` (username/phone/email), `password`, `target_aud` + client assertion |
| `POST` | `/auth/login/mobile` | `x-www-form-urlencoded` | SMS login: `phone`, `code`, `target_aud` + client assertion (auto-creates user if phone unknown) |
| `POST` | `/auth/token/refresh` | `x-www-form-urlencoded` | Rotate refresh token: `refresh_token` + client assertion |
| `POST` | `/auth/logout` | Bearer token | Revoke the current access token's session (carries jti for subscriber revocation) |
| `POST` | `/auth/logout-all` | `json` + Bearer | Revoke all of the user's sessions after password check, body: `{"password":"..."}` |

Login / refresh success response:

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 900 }
```

### Registration & Credentials

| Method | Path | Content-Type | Description |
|---|---|---|---|
| `POST` | `/auth/register` | `json` | Register / complete account, body: `{"phone","smsCode","username","email","password","app"}`; `app ∈ {careermate, ragforge}`; existing phone links and backfills |
| `POST` | `/auth/credential/set-password` | `json` + Bearer | Set / change password, body: `{"oldPassword","newPassword"}` |
| `POST` | `/auth/credential/bind-email` | `json` + Bearer | Bind email, body: `{"email","password"}` |
| `POST` | `/auth/credential/set-username` | `json` + Bearer | Set username (CJK allowed, 2–32 chars), body: `{"username"}` |

Registration response example:

```json
{ "userId": 1001, "linked": false, "message": "注册成功" }
```

### SMS Codes

| Method | Path | Content-Type | Description |
|---|---|---|---|
| `POST` | `/auth/sms/send` | `json` | Send code, body: `{"phone":"+8613800000000","scene":"login"}` |

`scene` values (parsed by `SmsScene`): `login` / `mobile_login`, `register`, `reset` / `password_reset`, `bind_phone`. Dev fixes the code to `123456`; prod stores it in Redis and calls Aliyun SMS.

### Password Reset

| Method | Path | Content-Type | Description |
|---|---|---|---|
| `POST` | `/auth/password/reset/init` | `json` | Start reset, body: `{"account"}` or with `phone` |
| `POST` | `/auth/password/reset/verify` | `json` | Verify code, body: `{"account","code"}` |
| `POST` | `/auth/password/reset/confirm` | `json` | Set new password and return tokens, body: `reset_ticket`, `new_password`, `target_aud` + client assertion |

### OAuth / Agent

| Method | Path | Content-Type | Description |
|---|---|---|---|
| `POST` | `/oauth/token-exchange` | `x-www-form-urlencoded` | RFC 8693 token exchange |
| `POST` | `/oauth/consents` | `json` + Bearer | Create agent consent |
| `GET` | `/oauth/consents` | Bearer | List current user's consents |
| `POST` | `/oauth/consents/{id}/revoke` | Bearer | Revoke consent |
| `POST` | `/oauth/delegation-token` | `x-www-form-urlencoded` | Issue agent token from consent |
| `POST` | `/oauth/introspect` | `x-www-form-urlencoded` | Token introspection: `token` + client assertion |
| `GET` | `/userinfo` | Bearer | Return the user info for the current token |

`/oauth/token-exchange` key fields:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_audience=ragforge-api
requested_scopes=rag:search
```

### Internal API

| Method | Path | Content-Type | Description |
|---|---|---|---|
| `POST` | `/internal/users/resolve-by-phone` | `x-www-form-urlencoded` | Exact resolve-by-phone for downstream member invites. Authorized clients only; exact hash match, returns a masked number, no pagination, no fuzzy search |

### JWKS / Health / Risk

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/jwks.json` | active / previous public keys, cached 1 hour |
| `GET` | `/actuator/health` | Spring Boot health endpoint |
| `POST` | `/risk/login-failure` | Record a login failure and return a captcha / rate-limit decision |
| `POST` | `/risk/location-warning` | Return an off-site login warning |

## Token Design

Main claims of a user access token:

- `iss`: `auth.issuer`
- `aud`: the requested `target_aud`
- `sub`: `user:<user_id>`
- `principal_type`: `user`
- `user_id`, `platform_role`, `rag_role`
- `scopes` (derived from `target_aud` and role)
- `session_id`, `session_version`
- `rag_readable_kb_ids`, `rag_writable_kb_ids`

> Note: `tenant_id` was removed in migration V9; tokens no longer carry a tenant dimension.

Default TTLs:

| Token | Config | Default |
|---|---|---:|
| Access Token | `AUTH_ACCESS_TOKEN_TTL_SECONDS` | 900s |
| Refresh Token | `AUTH_REFRESH_TOKEN_TTL_SECONDS` | 604800s |
| Exchange / Delegation Token | `AUTH_EXCHANGE_TOKEN_TTL_SECONDS` | 600s |

A refresh token rotates on every use; reusing an old one triggers replay detection and revokes the whole token family.

## Configuration

Core environment variables:

| Variable | Description | Default |
|---|---|---|
| `SERVER_PORT` | HTTP port | `8090` |
| `SPRING_PROFILES_ACTIVE` | profile (`dev` / `prod`) | `dev` |
| `AUTH_DB_URL` | PostgreSQL JDBC URL | `jdbc:postgresql://localhost:5432/authdb` |
| `AUTH_DB_USERNAME` / `AUTH_DB_PASSWORD` | DB credentials | `auth` / `auth_dev_password` |
| `SPRING_DATA_REDIS_HOST` / `SPRING_DATA_REDIS_PORT` | Redis connection | Spring Boot defaults |
| `AUTH_ISSUER` | JWT issuer | `https://auth.careermate.cn` |
| `AUTH_TOKEN_ENDPOINT_AUDIENCE` | client assertion `aud` | `https://auth.careermate.cn/oauth/token` |
| `JWKS_ACTIVE_KID` / `JWKS_ACTIVE_PRIVATE_KEY_PATH` | active key | `auth-active` / `config/keys/auth-active.pem` |
| `JWKS_PREVIOUS_KID` / `JWKS_PREVIOUS_PRIVATE_KEY_PATH` | previous key (may be empty in prod) | `auth-previous` / `config/keys/auth-previous.pem` |
| `AUTH_SMS_PHONE_HASH_PEPPER` | pepper for phone / code / IP hashing | `auth-gateway-dev-pepper` |
| `AUTH_RAGFORGE_EVENT_*` / `AUTH_CAREERMATE_EVENT_*` | event subscription endpoint and HMAC secret | prod only |
| `ALIYUN_SMS_*` | Aliyun SMS config | prod only |

See [deploy/env/auth-gateway.env.example](deploy/env/auth-gateway.env.example) for a production example.

## Database Migrations

Flyway migrations live in `src/main/resources/db/migration` (V1–V9):

| Version | Content |
|---|---|
| V1 | `auth_users`, `auth_sessions`, `refresh_tokens`, `oauth_clients`, `agent_consents`, `sms_codes`, `jti_blacklist` |
| V2–V3 | seed OAuth clients + `allowed_scopes` |
| V4 | `audit_logs` |
| V5 | event HTTP push (`event_subscriptions`, `event_outbox`) |
| V6 | session audience (historically included tenant, reverted in V9) |
| V7 | seed `event_subscriptions` |
| V8 | partial-unique indexes on account identifiers + app admission table `user_app_membership` (with backfill) |
| V9 | drop `auth_users.tenant_id` (de-tenant) |

Manual migration:

```bash
./mvnw flyway:migrate \
  -Dflyway.url=jdbc:postgresql://localhost:5433/authdb \
  -Dflyway.user=auth -Dflyway.password=auth_dev_password
```

## Auth Events

Current event types: `session.revoked`, `user.password.changed`, `consent.revoked`, `refresh.replay_detected`.

Delivery is HTTP POST JSON with headers:

| Header | Description |
|---|---|
| `X-Auth-Event-Signature` | `sha256=<hex hmac>` over the request body using the subscription's `hmac_secret` |
| `X-Auth-Event-Timestamp` | Unix seconds |

Before enabling `event_subscriptions.status='ACTIVE'` in production, every subscription must have a real `hmac_secret` of length ≥16; the `prod` profile rejects empty values and `<TBD...>` placeholders.

## Smoke Tests (local)

After the service starts:

```bash
./scripts/test-token-exchange.sh
./scripts/test-refresh-replay.sh
./scripts/e2e-userinfo-introspect.sh
./scripts/test-consent-flow.sh
./scripts/e2e-password-reset.sh
```

Seed a test SMS code straight into the DB:

```bash
AUTH_DB_PORT=5433 ./scripts/seed-test-sms-code.sh +8613800000000 123456 reset
```

## Build & Test

```bash
./mvnw test
./mvnw -DskipTests package
```

## CI/CD

Defined in [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml):

**Pull Request**

1. Semgrep security scan (OWASP Top Ten + secrets).
2. JDK 21 Maven `package`.
3. Unit tests against PostgreSQL 16 / Redis 7 services.

**Push to `main`**

1. Build and test.
2. Build the Docker image inside GitHub Actions and **push it to Aliyun ACR** (tag `auth-<sha12>`).
3. Upload the JAR, Dockerfile, scripts, and k8s manifests to Server 3 over an SSH jump through Server 2.
4. Server 3 pulls the image from ACR (via `acr-pull-secret`), refreshes the `auth-gateway-env` Secret, applies namespace / service / deployment, and rolls 2 Pods.
5. Smoke checks `/actuator/health` and `/.well-known/jwks.json`.

> The legacy "build the image on Server 3 and import into k3s containerd" path is kept as an offline fallback (the `USE_REMOTE_IMAGE=0` branch of `deploy-from-github.sh`); production defaults to pulling from ACR.

## Production Deployment

The production path is single-node k3s on Server 3. Full steps in [docs/deployment-auth-gateway.md](docs/deployment-auth-gateway.md). Key constraints:

- Never commit real DB passwords, Aliyun AK/SK, HMAC secrets, or RSA private keys to Git.
- `/opt/auth-gateway/keys/auth-active.pem` is host-mounted into the container; container user `10001:10001`, key dir `700`, private key `640`.
- With `SPRING_PROFILES_ACTIVE=prod`, codes are stored in Redis and signing client assertions with the local dev key is forbidden.
- Key rotation: configure the previous key first, then switch the active key, so downstream JWKS caches transition smoothly.

## License

Internal project, no open-source license attached. Confirm with the maintainer before external distribution.
