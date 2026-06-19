# Auth Gateway

Independent Spring Boot authentication gateway for CareerMate and RAGForge.

## Runtime

- Java 17
- Spring Boot 3.2.x
- HTTP port: `8090`
- Postgres: independent `authdb` instance exposed on host port `5433`
- Redis: independent instance exposed on host port `6380`, using logical DB `1` for application data

## Local Start

Start middleware:

```bash
docker-compose up -d postgres redis
```

Run the service:

```bash
./mvnw spring-boot:run
```

Health check:

```bash
curl -s http://localhost:8090/actuator/health | jq .status
```

## Event Subscriptions

Before production rollout, replace `event_subscriptions.hmac_secret` with random strings of at least 32 characters that match downstream services (`rag-forge` / `careermate`). Use an SQL `UPDATE` or operations-managed secret injection; empty values and `<TBD...>` placeholders are rejected at startup outside the dev profile.
