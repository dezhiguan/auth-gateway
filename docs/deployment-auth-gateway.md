# Auth Gateway Deployment Guide

## 1. Topology

Auth Gateway is deployed on Server 3 with CareerMate and RAGForge app services.

| Layer | Private IP | Services |
|---|---:|---|
| Server 1 Data | `172.25.90.183` | PostgreSQL `authdb`, Redis |
| Server 2 Ingress | `172.19.40.32` | Nginx public entry `https://auth.careermate.cn` |
| Server 3 App | `172.25.90.184` | `auth-gateway` replicas on `8090/8091/8092` |

Public traffic:

```text
auth.careermate.cn
  -> Server 2 Nginx
  -> Server 3 auth-gateway upstream :8090/:8091/:8092
```

## 2. Repository Artifacts

Important files:

```text
.github/workflows/ci-cd.yml
Dockerfile
deploy/docker/docker-compose.auth-gateway.example.yml
deploy/env/auth-gateway.env.example
deploy/nginx/auth-gateway.conf.example
deploy/scripts/deploy-from-github.sh
deploy/scripts/rollback-auth-gateway.sh
deploy/sql/init-authdb.sql.example
```

Build locally:

```bash
./mvnw -DskipTests package
docker build -t auth-gateway:latest .
```

## 3. Server 1 Prerequisites

Create the production database on Server 1:

```bash
psql -h 127.0.0.1 -U postgres -f deploy/sql/init-authdb.sql.example
```

Production values:

```bash
AUTH_DB_URL=jdbc:postgresql://172.25.90.183:5432/authdb
AUTH_DB_USERNAME=auth
AUTH_DB_PASSWORD=<server-local-secret>
SPRING_DATA_REDIS_HOST=172.25.90.183
SPRING_DATA_REDIS_PORT=6379
```

## 4. Server 3 Directories

Create once:

```bash
sudo mkdir -p \
  /opt/auth-gateway/releases \
  /opt/auth-gateway/scripts \
  /opt/auth-gateway/keys \
  /opt/auth-gateway/logs \
  /opt/shared/env
sudo chmod 700 /opt/auth-gateway/keys
```

Expected layout:

```text
/opt/auth-gateway/
  current -> releases/<git-sha>/
  releases/<git-sha>/
    app.jar
    Dockerfile
  docker-compose.yml
  keys/
    auth-active.pem
    auth-previous.pem        # optional, for key rotation
  logs/
  scripts/
    deploy-from-github.sh
    rollback-auth-gateway.sh

/opt/shared/env/
  common.env
  auth-gateway.env
```

Copy `deploy/docker/docker-compose.auth-gateway.example.yml` to:

```text
/opt/auth-gateway/docker-compose.yml
```

Copy `deploy/env/auth-gateway.env.example` to:

```text
/opt/shared/env/auth-gateway.env
```

Then replace all `<CHANGE_ME_...>` values.

## 5. Required Production Config

`/opt/shared/env/auth-gateway.env` must include:

```bash
SPRING_PROFILES_ACTIVE=prod
AUTH_DB_URL=jdbc:postgresql://172.25.90.183:5432/authdb
AUTH_DB_USERNAME=auth
AUTH_DB_PASSWORD=<secret>
SPRING_DATA_REDIS_HOST=172.25.90.183
AUTH_ISSUER=https://auth.careermate.cn
AUTH_TOKEN_ENDPOINT_AUDIENCE=https://auth.careermate.cn/oauth/token
JWKS_ACTIVE_KID=auth-active
JWKS_ACTIVE_PRIVATE_KEY_PATH=/opt/auth-gateway/keys/auth-active.pem
AUTH_SMS_PHONE_HASH_PEPPER=<random-secret>
ALIYUN_SMS_ACCESS_KEY_ID=<secret>
ALIYUN_SMS_ACCESS_KEY_SECRET=<secret>
ALIYUN_SMS_SIGN_NAME=CareerMate
ALIYUN_SMS_TEMPLATE_CODE=SMS_XXXXXX
```

Do not store real secrets in GitHub repository files.

## 6. JWKS Keys

Generate keys locally or on Server 3:

```bash
./scripts/gen-keys.sh
```

Install private keys on Server 3:

```bash
sudo cp config/keys/auth-active.pem /opt/auth-gateway/keys/auth-active.pem
sudo chown 10001:10001 /opt/auth-gateway/keys/auth-active.pem
sudo chmod 640 /opt/auth-gateway/keys/auth-active.pem
```

Key rotation:

1. Put the new private key in `/opt/auth-gateway/keys/auth-active.pem`.
2. Move the old active key to `/opt/auth-gateway/keys/auth-previous.pem`.
3. Set `JWKS_PREVIOUS_KID` and `JWKS_PREVIOUS_PRIVATE_KEY_PATH`.
4. Deploy and verify `/.well-known/jwks.json` exposes both keys during the overlap window.

## 7. GitHub Actions Secrets

Set repository secrets:

| Secret | Description |
|---|---|
| `AUTH_GATEWAY_APP_SSH_KEY` | SSH private key for Server 3 deploy |
| `AUTH_GATEWAY_APP_HOST` | Server 3 private or reachable host |
| `AUTH_GATEWAY_APP_USER` | SSH user on Server 3 |
| `AUTH_GATEWAY_APP_PORT` | SSH port, optional |
| `CAREERMATE_INGRESS_HOST` | Server 2 jump host |
| `CAREERMATE_INGRESS_USER` | Server 2 jump user |
| `CAREERMATE_INGRESS_PORT` | Server 2 jump port, optional |

Set repository variable:

| Variable | Default |
|---|---|
| `AUTH_GATEWAY_BASE_URL` | `https://auth.careermate.cn` |

## 8. CI/CD Flow

On pull request:

1. Semgrep security scan.
2. JDK 21 Maven package.
3. Unit tests with PostgreSQL and Redis services.

On push to `main`:

1. Build and test.
2. Upload JAR to Server 3 release directory.
3. Upload `Dockerfile` and deployment scripts.
4. Build Docker image on Server 3.
5. Rolling restart:
   - `auth-gateway-1` -> `8090`
   - `auth-gateway-2` -> `8091`
   - `auth-gateway-3` -> `8092`
6. Smoke checks:
   - `/actuator/health`
   - `/.well-known/jwks.json`

## 9. Manual Deploy

After CI uploads release files:

```bash
sudo bash /opt/auth-gateway/scripts/deploy-from-github.sh <git-sha>
```

Manual rollback:

```bash
sudo bash /opt/auth-gateway/scripts/rollback-auth-gateway.sh /opt/auth-gateway/releases/<previous-sha>
```

## 10. Nginx Upstream

Server 2 Nginx should route `auth.careermate.cn` to the Server 3 replicas:

Use `deploy/nginx/auth-gateway.conf.example` as the base config.

```nginx
upstream auth_gateway_backend {
    server 172.25.90.184:8090;
    server 172.25.90.184:8091;
    server 172.25.90.184:8092;
}

server {
    server_name auth.careermate.cn;

    location / {
        proxy_pass http://auth_gateway_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

If Server 2 cannot directly reach Server 3 private ports, keep the same tunnel approach used by CareerMate and point the upstream at Server 2 local tunnel ports.

## 11. Verification

From Server 3:

```bash
curl -fsS http://127.0.0.1:8090/actuator/health
curl -fsS http://127.0.0.1:8091/actuator/health
curl -fsS http://127.0.0.1:8092/actuator/health
curl -fsS http://127.0.0.1:8090/.well-known/jwks.json
```

From public network:

```bash
curl -fsS https://auth.careermate.cn/actuator/health
curl -fsS https://auth.careermate.cn/.well-known/jwks.json
```

Protocol smoke scripts:

```bash
./scripts/test-token-exchange.sh
./scripts/test-refresh-replay.sh
./scripts/e2e-userinfo-introspect.sh
./scripts/test-consent-flow.sh
```

## 12. Deployment Checklist

- Server 1 `authdb` exists and Flyway can migrate.
- Server 1 Redis is reachable from Server 3.
- `/opt/shared/env/auth-gateway.env` exists and contains no placeholders.
- `/opt/auth-gateway/keys/auth-active.pem` exists and is readable by container UID/GID `10001:10001` (mode `640`).
- `/opt/auth-gateway/docker-compose.yml` exists.
- GitHub Actions secrets are configured.
- Nginx routes `auth.careermate.cn` to Server 3 replicas.
- Public `/.well-known/jwks.json` returns `keys`.
