# PCM Quick Start Guide

This guide will help you get **PCM (Profile & Consent Manager)** running locally — either fully via Docker or in hybrid mode (infrastructure in Docker, app on the JVM).

## Prerequisites

- **Docker & Docker Compose v2** (required)
- **Java 21 + Maven 3.9+** (only for hybrid / development mode)
- **curl or Postman** (for testing APIs)

---

## Option A — Full Docker (recommended)

Everything runs in containers: the PCM application, PostgreSQL, Vault, Keycloak, and the observability stack.

### 1. Configure secrets

```bash
cp .env.example .env
# Edit .env and replace every CHANGE_ME value
```

### 2. Build & start

```bash
docker compose up --build -d
```

The first build compiles the full Maven project inside Docker (~3-5 min). Subsequent builds are fast thanks to layer caching.

### 3. Check health

```bash
curl http://localhost:8080/actuator/health
# → {"status":"UP"}
```

### 4. Optional dev tools (pgAdmin)

```bash
docker compose --profile tools up -d pgadmin
# pgAdmin → http://localhost:5050
```

---

## Option B — Hybrid (infrastructure in Docker, app on JVM)

Faster iteration cycle: only the backing services run in Docker.

### 1. Start infrastructure only

```bash
docker compose up -d postgresql vault keycloak prometheus grafana jaeger otel-collector
```

### 2. Build the application

```bash
./mvnw clean install -DskipTests
```

### 3. Run the application

```bash
./mvnw spring-boot:run -pl pcm-infrastructure-spring
```

The application starts on **port 8080**.

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

| Service | URL | Description |
|---------|-----|-------------|
| PCM API | http://localhost:8080 | All REST endpoints |
| Actuator health | http://localhost:8080/actuator/health | Health check |
| Prometheus metrics | http://localhost:8080/actuator/prometheus | Raw metrics |
| Keycloak | http://localhost:8090/auth | IAM console |
| Vault | http://localhost:8200 | Secrets UI |
| Prometheus | http://localhost:9090 | Metrics query |
| Grafana | http://localhost:3000 | Dashboards |
| Jaeger | http://localhost:16686 | Distributed traces |
| pgAdmin | http://localhost:5050 | DB admin (tools profile) |

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

# Restart only the app (after a code change + rebuild)
docker compose up --build -d pcm

# Stop everything and remove volumes (clean slate)
docker compose down -v

# Scale down to just the essentials
docker compose stop grafana jaeger otel-collector prometheus
```

---

> In development mode, security is relaxed for some endpoints. In production, all requests require a valid JWT issued by Keycloak. See `application-prod.yml` for the production profile.
