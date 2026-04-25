# PCM Quick Start Guide

This guide will help you get **PCM (Profile & Consent Manager)** running on your local machine for development and testing.

## Prerequisites

- **Java 21** (required for virtual threads and modern syntax)
- **Maven 3.9+**
- **Docker & Docker Compose**
- **curl or Postman** (for testing APIs)

---

## 1. Start Infrastructure

PCM relies on PostgreSQL, Redis, Kafka, and optionally Vault. A pre-configured `docker-compose.yml` starts everything:

```bash
# From the project root
docker-compose up -d
```

This starts:
- **PostgreSQL** — primary database (port 5432)
- **Redis** — caching (port 6379)
- **Kafka** — messaging (port 9092)
- **HashiCorp Vault** — secrets & key management (port 8200)
- **OpenTelemetry Collector** — observability (port 4318)
- **Jaeger** — distributed tracing UI at `http://localhost:16686`
- **Prometheus** — metrics at `http://localhost:9090`
- **Grafana** — dashboards at `http://localhost:3000`

---

## 2. Build the Platform

```bash
mvn clean install -DskipTests
```

This builds all modules: the four bounded contexts (`preference`, `profile`, `consent`, `segment`) and the unified Spring Boot application (`pcm-infrastructure-spring`).

---

## 3. Run the Application

PCM is a **single deployable artifact** — one Spring Boot application serving all bounded contexts:

```bash
mvn spring-boot:run -pl pcm-infrastructure-spring
```

The application starts on **port 8080** by default.

Health check:
```bash
curl http://localhost:8080/actuator/health
```

---

## 4. Your First API Calls

### Create a Profile

```bash
curl -X POST http://localhost:8080/api/v1/profiles \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: default" \
  -d '{
    "id": "550e8400-e29b-41d4-a716-446655440000",
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
    "profileId": "550e8400-e29b-41d4-a716-446655440000",
    "tenantId": "default",
    "purpose": "MARKETING",
    "scope": "EMAIL"
  }'
```

### Verify Consent

```bash
curl "http://localhost:8080/api/v1/consents/verify?consentId=<consent-id>" \
  -H "X-Tenant-Id: default"
```

---

## 5. Useful Endpoints

| Endpoint | Description |
|----------|-------------|
| `http://localhost:8080/api/v1/profiles` | Profile API |
| `http://localhost:8080/api/v1/consents` | Consent API |
| `http://localhost:8080/api/v1/preferences` | Preference API |
| `http://localhost:8080/api/v1/segments` | Segment API |
| `http://localhost:8080/actuator/health` | Health check |
| `http://localhost:8080/actuator/metrics` | Prometheus metrics |
| `http://localhost:16686` | Jaeger tracing UI |
| `http://localhost:3000` | Grafana dashboards |

---

## 6. Running Tests

```bash
# All tests
mvn test

# Domain tests only (no Spring context, fast)
mvn test -pl consent-context/consent-domain
mvn test -pl profile-context/profile-domain

# Full integration tests
mvn test -pl pcm-infrastructure-spring
```

---

## 7. Configuration

PCM uses environment variables for all configuration. Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | HTTP port | `8080` |
| `SPRING_DATASOURCE_URL` | Database URL | `jdbc:postgresql://localhost:5432/pcm_db` |
| `SPRING_DATASOURCE_USERNAME` | DB username | `pcm` |
| `SPRING_DATASOURCE_PASSWORD` | DB password | `pcm_dev_password` |
| `PCM_ENCRYPTION_PROVIDER` | KMS provider (`vault`, `aws`, `azure`, `gcp`, `local`) | `local` |
| `VAULT_URI` | Vault address | `http://localhost:8200` |

See [Infrastructure Portability](PORTABILITY.md) for the full configuration reference.

---

> **Note**: In development mode, security is relaxed for some endpoints. In production, all requests require a valid JWT issued by Keycloak.
