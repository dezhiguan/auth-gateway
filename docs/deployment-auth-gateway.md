# Auth Gateway Deployment Guide

## 1. Topology

Auth Gateway runs on Server 3 single-node k3s with CareerMate and RAGForge app services.

| Layer | Private IP | Services |
|---|---:|---|
| Server 1 Data | `172.25.90.183` | PostgreSQL `authdb`, Redis |
| Server 2 Ingress | `172.19.40.32` | Nginx public entry `auth.careermate.cn` |
| Server 3 App | `172.25.90.184` | k3s `auth-gateway` Deployment, NodePort `31091` |

Public traffic:

```text
auth.careermate.cn
  -> Server 2 ragforge-nginx container
  -> Server 3 172.25.90.184:31091
  -> k3s Service auth-gateway
  -> 3 auth-gateway Pods
```

## 2. Repository Artifacts

Important files:

```text
.github/workflows/ci-cd.yml
Dockerfile
deploy/env/auth-gateway.env.example
deploy/k8s/auth-gateway/namespace.yaml
deploy/k8s/auth-gateway/deployment.yaml
deploy/k8s/auth-gateway/service.yaml
deploy/nginx/auth-gateway.conf.example
deploy/scripts/create-auth-gateway-k8s-secret.sh
deploy/scripts/deploy-from-github.sh
deploy/scripts/rollback-auth-gateway.sh
deploy/sql/init-authdb.sql.example
```

`deploy/docker/docker-compose.auth-gateway.example.yml` is retained as a legacy reference only. The production deploy path is k3s.

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

## 4. Server 3 Prerequisites

Create once:

```bash
sudo mkdir -p \
  /opt/auth-gateway/releases \
  /opt/auth-gateway/scripts \
  /opt/auth-gateway/deploy/k8s/auth-gateway \
  /opt/auth-gateway/keys \
  /opt/auth-gateway/logs/k8s \
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
  deploy/k8s/auth-gateway/
    namespace.yaml
    deployment.yaml
    service.yaml
  keys/
    auth-active.pem
    auth-previous.pem        # optional, for key rotation
  logs/k8s/
  scripts/
    create-auth-gateway-k8s-secret.sh
    deploy-from-github.sh
    rollback-auth-gateway.sh

/opt/shared/env/
  common.env
  auth-gateway.env
```

Server 3 must have Docker and k3s installed. The deploy script builds the Docker image on Server 3, imports it into k3s containerd, then rolls the k3s Deployment.

## 5. Required Production Config

`/opt/shared/env/auth-gateway.env` must include:

```bash
SPRING_PROFILES_ACTIVE=prod
AUTH_DB_URL=jdbc:postgresql://172.25.90.183:5432/authdb
AUTH_DB_USERNAME=auth
AUTH_DB_PASSWORD=<secret>
SPRING_DATA_REDIS_HOST=172.25.90.183
SPRING_DATA_REDIS_PORT=6379
AUTH_ISSUER=https://auth.careermate.cn
AUTH_TOKEN_ENDPOINT_AUDIENCE=https://auth.careermate.cn/oauth/token
JWKS_ACTIVE_KID=auth-active
JWKS_ACTIVE_PRIVATE_KEY_PATH=/opt/auth-gateway/keys/auth-active.pem
AUTH_SMS_PHONE_HASH_PEPPER=<random-secret>
ALIYUN_SMS_ACCESS_KEY_ID=<secret>
ALIYUN_SMS_ACCESS_KEY_SECRET=<secret>
ALIYUN_SMS_SIGN_NAME=CareerMate
ALIYUN_SMS_TEMPLATE_CODE=SMS_XXXXXX
JAVA_TOOL_OPTIONS="-Xms128m -Xmx256m"
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

The k3s Deployment mounts `/opt/auth-gateway/keys` read-only into each Pod.

## 7. GitHub Actions Secrets

Required repository secrets:

| Secret | Description |
|---|---|
| `AUTH_GATEWAY_APP_SSH_KEY` | SSH private key for Server 3 deploy |
| `AUTH_GATEWAY_APP_HOST` | Server 3 host, usually `172.25.90.184` if reachable through jump host |
| `AUTH_GATEWAY_APP_USER` | SSH user on Server 3, optional if root fallback is acceptable |
| `AUTH_GATEWAY_APP_PORT` | SSH port, optional, defaults to `22` |
| `CAREERMATE_INGRESS_HOST` | Server 2 jump host |
| `CAREERMATE_INGRESS_USER` | Server 2 jump user, optional, defaults to `root` |
| `CAREERMATE_INGRESS_PORT` | Server 2 jump port, optional, defaults to `22` |

Optional repository variable:

| Variable | Default |
|---|---|
| `AUTH_GATEWAY_BASE_URL` | `http://auth.careermate.cn` |

## 8. CI/CD Flow

On pull request:

1. Semgrep security scan.
2. JDK 21 Maven package.
3. Unit tests with PostgreSQL and Redis services.

On push to `main`:

1. Build and test.
2. Upload JAR, Dockerfile, scripts, and k8s manifests to Server 3.
3. Build Docker image on Server 3.
4. Import the image into k3s containerd.
5. Create/update `auth-gateway-env` Secret from `/opt/shared/env/common.env` and `/opt/shared/env/auth-gateway.env`.
6. Apply namespace, service, deployment.
7. Roll out 3 Pods.
8. Smoke checks:
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

Server 2 Nginx should route `auth.careermate.cn` to Server 3 k3s NodePort:

```nginx
upstream auth_gateway_backend {
    server 172.25.90.184:31091;
}

server {
    server_name auth.careermate.cn;

    location / {
        proxy_pass http://auth_gateway_backend;
        proxy_set_header Host auth.careermate.cn;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Use `deploy/nginx/auth-gateway.conf.example` as the base config.

## 11. Verification

From Server 3:

```bash
k3s kubectl -n auth-gateway get pods -o wide
k3s kubectl -n auth-gateway get svc,endpoints
curl -fsS http://127.0.0.1:31091/actuator/health
curl -fsS http://127.0.0.1:31091/.well-known/jwks.json
```

From public network:

```bash
curl -fsS http://auth.careermate.cn/actuator/health
curl -fsS http://auth.careermate.cn/.well-known/jwks.json
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
- Nginx routes `auth.careermate.cn` to `172.25.90.184:31091`.
- Public `/.well-known/jwks.json` returns `keys`.
