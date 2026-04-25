# Framework Adapter Implementation Checklist

Use this checklist when implementing a new infrastructure adapter for PCM. Each item maps to a concrete deliverable. The Spring Boot adapter (`pcm-infrastructure-spring`) is the reference implementation — check it when in doubt.

---

## Module Setup

- [ ] Create `pcm-infrastructure-{framework}/` Maven module
- [ ] Add module to root `pom.xml` `<modules>` section
- [ ] Declare dependencies on all four `*-infrastructure` modules in the new module's `pom.xml`
- [ ] Add framework-specific dependencies (web, persistence, DI, transactions)
- [ ] Verify domain and application modules are **not** directly referenced (they come transitively)
- [ ] Confirm `mvn dependency:tree` shows zero Spring/Quarkus deps in `*-domain` or `*-application` modules

---

## Persistence Layer — Per Bounded Context (×4)

Repeat for: **Preference**, **Profile**, **Consent**, **Segment**

- [ ] Create persistence entity class with framework annotations (`@Entity` / Panache entity)
- [ ] Apply table name with bounded context prefix (`preference_`, `profile_`, `consent_`, `segment_`)
- [ ] Add audit fields (`createdAt`, `updatedAt`) using framework auditing support
- [ ] Add `@Version` field for optimistic locking
- [ ] Create `{Context}Mapper` with `toJpaEntity()` and `toDomainEntity()` static methods
- [ ] Mapper uses `reconstitute()` factory method — never `new DomainEntity()`
- [ ] Mapper unwraps value objects to primitives on write (`getId().getValue()`)
- [ ] Mapper wraps primitives back to value objects on read (`ProfileId.of(uuid)`)
- [ ] Implement the domain `{Context}Repository` interface in an adapter class
- [ ] Repository adapter delegates to framework persistence, translates via mapper
- [ ] Write a round-trip test: `domain → persistence → domain` produces equal entity

---

## Dependency Injection — Per Bounded Context (×4)

Repeat for: **Preference**, **Profile**, **Consent**, **Segment**

- [ ] Create `{Context}UseCaseConfiguration` (Spring `@Configuration` / Quarkus `@ApplicationScoped` producer)
- [ ] Wire each use case via constructor — no `@Autowired` on use case classes
- [ ] Inject `{Context}Repository` implementation into use cases that need it
- [ ] Inject `EventPublisher` implementation into use cases that publish events
- [ ] Verify use cases are instantiable with `new UseCase(mockRepo)` in plain unit tests

**Spring Boot reference:** `PreferenceUseCaseConfiguration`, `ProfileUseCaseConfiguration`, `SegmentUseCaseConfiguration`

---

## Transaction Management

- [ ] Implement transaction wrapping **without** adding `@Transactional` to use case classes
- [ ] Write operations (`execute*`, `save*`, `delete*`, `grant*`, `revoke*`, `erase*`) use `PROPAGATION_REQUIRED` with rollback on `Exception`
- [ ] Read operations (`get*`, `find*`, `verify*`) use `PROPAGATION_REQUIRED, readOnly`
- [ ] Verify: exception in use case rolls back the transaction
- [ ] Verify: successful use case execution commits the transaction

**Spring Boot reference:** `TransactionConfiguration` (uses `TransactionInterceptor` + `BeanNameAutoProxyCreator`)

---

## Event Bus

- [ ] Implement `EventPublisher` interface from `preference-application`
- [ ] Implementation uses framework event mechanism (Spring `ApplicationEventPublisher` / CDI `Event<Object>`)
- [ ] Events are delivered within the same transaction (use `@TransactionalEventListener` or equivalent)
- [ ] Register implementation as a managed bean so it can be injected into use cases
- [ ] Write a test verifying event delivery and rollback behavior

**Spring Boot reference:** `SpringEventPublisher`, `PreferenceEventHandler`

---

## REST Layer — Per Bounded Context (×4)

Repeat for: **Preference**, **Profile**, **Consent**, **Segment**

- [ ] Create controller / resource class with framework web annotations
- [ ] Map all existing endpoints (verify paths, HTTP methods, and status codes match the API reference)
- [ ] Inject use cases via constructor (Spring) or field injection (Quarkus CDI)
- [ ] Controllers contain zero business logic — delegate entirely to use cases
- [ ] Pass `X-Tenant-Id` header through to use case requests where required

**Endpoint inventory:** see `docs/API_REFERENCE.md`

---

## Exception Handling

- [ ] Implement exception mapper / advice for all domain exception types
- [ ] All error responses use `Content-Type: application/problem+json`
- [ ] Response body follows RFC 7807: `type`, `title`, `status`, `detail`, `instance`
- [ ] Include `timestamp` extension field
- [ ] Include `fieldErrors` extension field for validation exceptions (pure-assert typed exceptions)
- [ ] `PreferenceNotFoundException` → 404
- [ ] `ProfileNotFoundException` → 404
- [ ] `ConsentNotFoundException` → 404
- [ ] `SegmentNotFoundException` → 404
- [ ] `ProfileDeletedException` → 410
- [ ] `InvalidHandleException` → 400
- [ ] `StringTooShortException` (pure-assert) → 400
- [ ] `InvalidPatternException` (pure-assert) → 400
- [ ] `ConsentRevokedException` → 409

**Spring Boot reference:** `ProblemDetailExceptionHandler`

---

## Configuration

- [ ] Implement `PreferenceConfiguration` interface using framework config mechanism
- [ ] Implement `ProfileConfiguration` interface
- [ ] Implement `ConsentConfiguration` interface
- [ ] Configuration fails fast at startup if required values are missing or invalid
- [ ] Configuration values are identical to the Spring Boot adapter defaults

---

## Validation

- [ ] Run `mvn clean verify` — all tests pass
- [ ] Domain tests run without framework context (no Spring/Quarkus test annotations in `*-domain` test classes)
- [ ] Domain tests complete in under 100ms per test class
- [ ] Integration tests verify all four bounded contexts work end-to-end
- [ ] API contract tests confirm request/response schemas are unchanged vs. Spring Boot adapter
- [ ] Database schema is unchanged (same tables, same columns, same indexes)
- [ ] Performance: request latency within 5% of Spring Boot adapter baseline
- [ ] Performance: mapper translation under 1ms per entity

---

## Documentation

- [ ] Update `docs/PORTABILITY.md` with new framework section
- [ ] Add ADR documenting the decision to support the new framework
- [ ] Update `README.md` with build and run instructions for the new adapter
