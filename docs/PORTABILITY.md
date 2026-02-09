# Infrastructure Portability & Configuration

PCM is designed to be highly portable and infrastructure-agnostic. This document explains how to switch between different infrastructure providers using environment variables.

## 1. Messaging (Kafka vs RabbitMQ)

PCM uses Spring Cloud Stream to abstract the messaging layer.

| Provider | Enabled via environment variables |
| :--- | :--- |
| **Kafka** (Default) | `SPRING_CLOUD_STREAM_BINDER=kafka`, `KAFKA_BOOTSTRAP_SERVERS` |
| **RabbitMQ** | `SPRING_CLOUD_STREAM_BINDER=rabbit`, `RABBITMQ_HOST`, `RABBITMQ_PORT`, `RABBITMQ_USERNAME`, `RABBITMQ_PASSWORD` |

---

## 2. Database (PostgreSQL vs MySQL)

The database layer has been generalized to support any major relational database.

| Setting | Variable | Default |
| :--- | :--- | :--- |
| **URL** | `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:8843/pcm_db` |
| **Username** | `DB_USERNAME` | `pcm` |
| **Password** | `DB_PASSWORD` | `pcm_dev_password` |
| **Dialect** | `DB_DIALECT` | `org.hibernate.dialect.PostgreSQLDialect` |

> [!TIP]
> To use MySQL, set `DB_DIALECT=org.hibernate.dialect.MySQLDialect` and update the connection URL.

---

## 3. PII Protection (Vault vs Local)

The Sensitive Data (PII) protection layer is abstracted.

| Provider | Variable | Description |
| :--- | :--- | :--- |
| **Vault** (Default) | `PII_PROTECTION_PROVIDER=vault` | Uses HashiCorp Vault Transit Engine. |
| **Local** | `PII_PROTECTION_PROVIDER=local` | Uses localized AES-128 encryption with a static key (`PII_LOCAL_SECRET`). |

---

## 4. Observability (OpenTelemetry)

Tracing and Metrics are standardized on the OpenTelemetry (OTLP) protocol.

| Setting | Variable | Default |
| :--- | :--- | :--- |
| **OTLP Endpoint** | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4318/v1/traces` |
| **Metrics Endpoint** | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | `http://localhost:4318/v1/metrics` |

---

## 5. Configuration (Centralized vs Decentralized)

| Mode | Import String | Description |
| :--- | :--- | :--- |
| **Centralized** | `spring.config.import=configserver:http://localhost:8888` | Fetches config from Config Service. |
| **Decentralized** | `spring.config.import=optional:configserver:...` | Falls back to local/env properties if Config Server is down. |
