# ADR 001: Hexagonal Architecture (Ports and Adapters)

## Status
Accepted

## Context
PCM is designed as a core underlying platform for multiple social and privacy-centric applications. It needs to be highly maintainable, testable, and decoupled from specific infrastructure choices (like switching from one KMS provider to another, or adding a Quarkus adapter alongside the existing Spring Boot one).

The platform is structured as a **modular monolith** with four bounded contexts (Profile, Consent, Segment, Preference), each compiled as independent Maven modules and deployed together as a single Spring Boot application.

## Decision
We adopt **Hexagonal Architecture** (Ports and Adapters) for all bounded contexts. Every context is divided into three distinct layers:

1. **Domain** (`{context}-domain`): Pure business logic — aggregates, value objects, domain events, repository interfaces. Zero dependencies on external frameworks. Validated with the Maven Enforcer plugin to ban Spring, JPA, and other framework imports.
2. **Application** (`{context}-application`): Use cases that coordinate domain entities and handle DTO mapping. Depends only on the domain layer. No `@Transactional`, no `@Autowired`, no framework annotations of any kind.
3. **Infrastructure** (`{context}-infrastructure` + `pcm-infrastructure-spring`): Adapters for databases (JPA/Hibernate), messaging (Spring events), and external clients. This is the only layer that knows about Spring Boot, JPA, or any other framework.

The domain and application layers are published as plain Java libraries. A new framework adapter (e.g., Quarkus) only needs to implement the infrastructure layer — the domain and application layers are reused unchanged.

## Consequences
- **Pros**:
  - Domain logic is protected from technological changes. Switching KMS providers, databases, or frameworks does not touch the domain.
  - Unit testing is fast and simple — domain tests run without a Spring context in under 100ms per class.
  - Property-based tests (jqwik) can exhaustively validate domain invariants without any mocking overhead.
  - The adapter pattern enables `pcm-tcf-adapter` and future external modules to build on PCM without modifying the core (see [ADR-004](adr-004-tcf-removal.md)).
- **Cons**:
  - Requires mapper boilerplate between domain entities and JPA entities.
  - Higher learning curve for developers unfamiliar with hexagonal architecture.
  - The Maven Enforcer plugin configuration must be maintained as new dependencies are added.

## Related ADRs
- [ADR-003: Infrastructure Abstraction](adr-003-infrastructure-abstraction.md) — how infrastructure adapters are wired without polluting the domain
- [ADR-004: TCF Removal](adr-004-tcf-removal.md) — example of the adapter pattern enabling clean separation of concerns
