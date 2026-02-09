# ADR 003: Infrastructure Abstraction Layer

## Status
Accepted

## Context
PCM aims to be a portable, open-source identity platform. The initial implementation was tightly coupled to specific infrastructure providers:
- **PostgreSQL** (specifically `JSONB` and index types)
- **Kafka** (hard dependency on binder-specific logic)
- **Vault** (mandatory for PII encryption)
- **Spring Cloud Config** (mandatory for bootstrap)
- **Brave/Zipkin** (specific tracing headers)

To increase adoption and deployment flexibility, we needed to abstract these layers.

## Decision
Implement a "Generic Infrastructure" layer using Spring Boot's abstraction capabilities:
1. **Config**: Use `optional:configserver` and environment variable fallbacks for a decentralized mode.
2. **Database**: Standardize on Hibernate 6 native JSON mapping and generic SQL types in migrations to support MySQL/MariaDB/Postgres.
3. **Messaging**: Use Spring Cloud Stream Binders to allow swappable backends (Kafka/RabbitMQ).
4. **Encryption**: Implement a `PIIProtectionProvider` interface to support Vault or local AES encryption.
5. **Observability**: Migrate to OpenTelemetry (OTLP) for vendor-neutral tracing and metrics.

## Consequences
- **Positive**: Simplified local development (no mandatory Config Server).
- **Positive**: Platform can be deployed on a wider range of Cloud managed services (RDS MySQL, Cloud PubSub, etc.).
- **Positive**: Future-proof observability using industry standards.
- **Negative**: Slight increase in dependency management overhead in the parent `pom.xml`.
- **Negative**: Need to maintain multiple binders/dialects if vendor-specific features are required.
