# PCM Quick Start Guide

This guide will help you get the **PCM (Profile & Consent Manager)** platform running on your local machine for development and testing.

## Prerequisites

- **Java 21** (Required for virtual threads and modern syntax)
- **Maven 3.9+**
- **Docker & Docker Compose**
- **Postman or curl** (for testing APIs)

## Automated Startup (Recommended)

We provide helper scripts to manage the full platform lifecycle.

```bash
# Start everything in order (Infrastructure -> Config -> Services)
./scripts/start-platform.sh

# Stop everything
./scripts/stop-platform.sh
```

## Manual Startup

## 1. Start Infrastructure

PCM relies on a few key infrastructure components. We provide a pre-configured `docker-compose.yml` to get them running instantly.

```bash
# From the project root
docker-compose up -d
```

This will start:
- **PostgreSQL/MySQL**: Storage (Port 8843)
- **Redis**: Caching (Port 6779)
- **Kafka**: Messaging (Port 9092)
- **RabbitMQ**: Alternative Messaging (Port 5672)
- **Elasticsearch**: Segmentation (Port 9200)
- **OpenTelemetry Collector**: Observability (Port 4318)
- **Jaeger**: Distributed Tracing (Port 16686)
- **Kafka UI**: `http://localhost:8095`

## 2. Build the Platform

Build all shared libraries and microservices using Maven:

```bash
mvn clean install -DskipTests
```

## 3. Run the Services

You can run each service individually. **Crucial**: Start the `config-service` first.

```bash
# Start Config Service (Port 8888)
cd config-service && mvn spring-boot:run

# Once Config Service is UP, start others:
cd ../profile-service && mvn spring-boot:run
cd ../api-gateway && mvn spring-boot:run
```

## 4. Your First API Calls

The **API Gateway** acts as the single entry point at `http://localhost:9880`.

### Create a Profile
```sh
curl -X POST http://localhost:9880/api/v1/profiles \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: vibe-afrika" \
  -d '{
    "handle": "koffi_jean",
    "attributes": {
      "displayName": "Koffi Jean Christ",
      "country": "Ivory Coast"
    }
  }'
```

### Get Unified User View ("Me")
PCM uses Keycloak for IAM. To call protected endpoints, you first need a JWT token:

```bash
# Get a token for pcm-admin
TOKEN=$(curl -s -X POST "http://localhost:8090/auth/realms/pcm/protocol/openid-connect/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=pcm-admin" \
     -d "password=pcm_admin_password" \
     -d "grant_type=password" \
     -d "client_id=pcm-gateway" | jq -r '.access_token')

# Access the "Me" aggregator
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: vibe-afrika" http://localhost:9880/api/v1/users/me
```

## 5. Useful Endpoints

| Service | Port | Documentation |
| :--- | :--- | :--- |
| **API Gateway** | 9880 | `http://localhost:9880/swagger-ui.html` |
| **Profile** | 18081 | `http://localhost:18081/swagger-ui.html` |
| **Preference**| 18082 | `http://localhost:18082/swagger-ui.html` |
| **Consent** | 18083 | `http://localhost:18083/swagger-ui.html` |
| **Segment** | 18084 | `http://localhost:18084/swagger-ui.html` |
| **Config** | 8888 | `http://localhost:8888/actuator/health` |
| **Tracing (Jaeger)** | 16686 | `http://localhost:16686/search` |
| **Rabbit UI** | 15672 | `http://localhost:15672` |

---
**Note**: In development mode, security is relaxed for some endpoints. In production, all requests except profile registration require a valid JWT.
