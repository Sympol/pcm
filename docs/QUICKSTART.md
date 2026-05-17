# PCM Quick Start Guide

Get **PCM (Profile & Consent Manager)** running locally in two commands.

## Prerequisites

- **Docker & Docker Compose v2**
- **Java 21 + Maven 3.9+** (only for hybrid / development mode)

---

## Option A — Full Docker (recommended)

Everything runs in containers: PCM, PostgreSQL, Vault, Keycloak, and the observability stack.
Vault is bootstrapped automatically — no manual setup required.

```bash
cp .env.example .env
docker compose up --build -d
```

The first build compiles the full Maven project inside Docker (~3–5 min).
Subsequent builds are fast thanks to layer caching.

Check that everything is up:

```bash
curl http://localhost:8080/actuator/health
# → {"status":"UP"}
```

Optional dev tools (pgAdmin):

```bash
docker compose --profile tools up -d pgadmin
# pgAdmin → http://localhost:5050
```

---

## Option B — Hybrid (infrastructure in Docker, app on JVM)

Faster iteration: only the backing services run in Docker.

```bash
# 1. Start infrastructure (Vault is bootstrapped automatically)
docker compose up -d postgresql vault vault-init keycloak

# 2. Build
./mvnw clean install -DskipTests

# 3. Run
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=pcm-dev-vault-token \
./mvnw spring-boot:run -pl pcm-infrastructure-spring
```

---

## Your First API Calls

### Create a Profile

```bash
curl -X POST http://localhost:8080/api/v1/profiles \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: default" \
  -d '{
    "handle": "koffi_jean",
    "attributes": {
      "displayName": "Koffi Jean Christ",
      "country": "Ivory Coast"
    }
  }'
```

### Grant Consent

```bash
curl -X POST http://localhost:8080/api/v1/consents \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: default" \
  -d '{
    "profileId": "<profile-id-from-above>",
    "tenantId": "default",
    "purpose": "MARKETING",
    "scope": "EMAIL"
  }'
```

### Export Personal Data (GDPR Art. 20)

```bash
curl http://localhost:8080/api/v1/profiles/<profile-id>/export \
  -H "X-Tenant-Id: default"
```

---

## Service URLs

| Service          | URL                                    | Description              |
|------------------|----------------------------------------|--------------------------|
| PCM API          | http://localhost:8080                  | All REST endpoints       |
| Health           | http://localhost:8080/actuator/health  | Health check             |
| Metrics          | http://localhost:8080/actuator/prometheus | Raw metrics           |
| Keycloak         | http://localhost:8090/auth             | IAM console              |
| Vault            | http://localhost:8200                  | Secrets UI               |
| Prometheus       | http://localhost:9090                  | Metrics query            |
| Grafana          | http://localhost:3000                  | Dashboards               |
| Jaeger           | http://localhost:16686                 | Distributed traces       |
| pgAdmin          | http://localhost:5050                  | DB admin (tools profile) |

---

## Running Tests

```bash
# Domain tests only (no Spring context, fast)
./mvnw test -pl consent-context/consent-domain
./mvnw test -pl profile-context/profile-domain

# Full integration tests (requires Docker for Testcontainers)
./mvnw test -pl pcm-infrastructure-spring
```

---

## Useful Docker Commands

```bash
# View PCM application logs
docker compose logs -f pcm

# Rebuild and restart only the app after a code change
docker compose up --build -d pcm

# Stop everything and remove volumes (clean slate)
docker compose down -v

# Scale down to essentials only
docker compose stop grafana jaeger otel-collector prometheus
```

---

> **Dev vs Production** — The `.env.example` defaults are intentionally simple for local use.
> Before deploying to staging or production, replace all passwords, set a real `BLIND_INDEX_GLOBAL_SALT`,
> and configure a proper KMS provider. See `application-prod.yml` and `docker/vault-config-prod.hcl`.
