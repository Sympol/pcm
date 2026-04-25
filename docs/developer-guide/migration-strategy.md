# Migration Strategy: Microservices to Modular Monolith

This document describes the phased approach for migrating PCM from four independent Spring Boot microservices to a single framework-agnostic modular monolith, including rollback procedures, validation criteria, and risk mitigation strategies.

---

## Overview

The migration consolidates four microservices (Preference, Profile, Consent, Segment) into a single PCM service. Each bounded context is extracted into pure domain and application modules, with a unified Spring Boot infrastructure adapter. The migration is designed to be incremental — one bounded context at a time — so the system remains operational throughout.

**Migration order:** Preference → Segment → Profile → Consent

This order was chosen by complexity: Preference has the fewest dependencies and is the simplest bounded context, making it the best candidate for establishing patterns. Consent is last because it has the most complex domain logic (immutable ledger, IAB TCF integration).

---

## Phase Overview

| Phase | Bounded Context | Duration | Status |
|-------|----------------|----------|--------|
| 1     | Preference     | 2 weeks  | Complete |
| 2     | Segment        | 2 weeks  | Complete |
| 3     | Profile        | 3 weeks  | Complete |
| 4     | Consent        | 3 weeks  | Complete |
| 5     | Cross-context validation | 1 week | In progress |

---

## Phase 1: Preference Context

### What changes
- Preference microservice is replaced by `preference-domain`, `preference-application`, and `preference-infrastructure` modules within the PCM monolith
- JPA annotations removed from domain entities; moved to `PreferenceJpaEntity` in infrastructure
- Repository interface extracted to domain layer; Spring Data implementation in infrastructure
- Table renamed with prefix: `preference_preferences`
- Internal event bus replaces any HTTP calls from/to Preference

### Validation criteria
- All existing Preference integration tests pass without modification
- REST API contracts unchanged (paths, methods, request/response schemas, status codes)
- Database schema unchanged (Flyway migration confirms no structural changes)
- Domain tests run in under 100ms without Spring context
- Request latency within 5% of pre-migration baseline

### Rollback procedure
1. Stop the PCM monolith deployment
2. Redeploy the original Preference microservice JAR from the last known-good tag
3. Restore the original database connection string for the Preference service
4. Verify health endpoint responds: `GET /actuator/health`
5. Run smoke tests against the Preference API
6. Investigate root cause before re-attempting migration

**Rollback trigger:** Any of the following conditions warrant rollback:
- Integration test failure rate > 0%
- API contract mismatch detected
- Database schema divergence
- p99 latency increase > 10%

---

## Phase 2: Segment Context

### What changes
- Segment microservice replaced by `segment-domain`, `segment-application`, `segment-infrastructure` modules
- Table prefix applied: `segment_segments`, `segment_criteria`
- Inter-context communication: Segment subscribes to `PreferenceCreatedEvent` via internal event bus (replaces HTTP call)
- `ProfileEventSubscriber` added to handle profile events for segment evaluation

### Validation criteria
- All Segment integration tests pass
- Inter-context event flow verified: creating a preference triggers segment evaluation
- Event delivery confirmed within the same database transaction
- Rollback of a failed preference creation does not trigger segment evaluation
- API contracts unchanged

### Rollback procedure
1. Stop PCM monolith
2. Redeploy original Segment microservice
3. Restore Segment service database connection
4. Restore any HTTP-based integration between Preference and Segment services
5. Verify both services healthy and communicating
6. Run smoke tests

**Additional risk:** The event bus replaces a network call. If the event bus has a defect, segment evaluation silently stops. Monitor segment evaluation metrics after deployment.

---

## Phase 3: Profile Context

### What changes
- Profile microservice replaced by `profile-domain`, `profile-application`, `profile-infrastructure` modules
- Table prefix applied: `profile_profiles`
- GDPR erasure (`Profile.erase()`) implemented as domain operation
- Handle validation enforced in `Handle` value object using pure-assert
- `ProfileJpaEntity` uses `@JdbcTypeCode(SqlTypes.JSON)` for attributes map

### Validation criteria
- All Profile integration tests pass
- GDPR erasure test: erased profile has anonymized handle and empty attributes
- Handle uniqueness enforced across tenant boundary
- `ProfileDeletedException` (410 Gone) returned for operations on erased profiles
- API contracts unchanged
- Database schema unchanged

### Rollback procedure
1. Stop PCM monolith
2. Redeploy original Profile microservice
3. Restore Profile service database connection
4. Verify health endpoint
5. Run smoke tests including GDPR erasure flow
6. Check that Segment's profile event subscriber is disabled or re-pointed to HTTP

**Additional risk:** Profile is referenced by Preference and Segment contexts. Rollback of Profile while Preference and Segment remain in the monolith requires careful coordination — the event bus subscribers in Segment must be disabled or made resilient to missing profile data.

---

## Phase 4: Consent Context

### What changes
- Consent microservice replaced by `consent-domain`, `consent-application`, `consent-infrastructure` modules
- Table prefix applied: `consent_consents`, `consent_events`
- Immutable ledger pattern: consent events are append-only
- IAB TCF v2.2 integration preserved in `ProcessTCFConsentUseCase`
- `ConsentJpaEntity` and `ConsentEventJpaEntity` for ledger persistence

### Validation criteria
- All Consent integration tests pass
- IAB TCF consent string parsing and validation works correctly
- Ledger integrity: consent history is append-only, no updates to existing records
- `ConsentRevokedException` (409) returned for operations on revoked consents
- API contracts unchanged
- TCF v2.2 compliance verified

### Rollback procedure
1. Stop PCM monolith
2. Redeploy original Consent microservice
3. Restore Consent service database connection
4. Verify IAB TCF integration endpoint responds correctly
5. Run smoke tests including TCF consent flow
6. Verify consent history integrity

**Additional risk:** The consent ledger is append-only. Any records written during the monolith deployment remain in the database after rollback. The original microservice must be able to read these records — verify schema compatibility before rollback.

---

## Phase 5: Cross-Context Validation

### What changes
- No new code changes — validation and documentation only
- All four bounded contexts running together in the monolith
- Full end-to-end integration tests across all contexts

### Validation criteria
- All unit, property, and integration tests pass across all four contexts
- Module dependency rules verified: domain → nothing, application → domain only, infrastructure → domain + application
- Maven enforcer confirms no framework dependencies in domain/application modules
- Performance baseline: all endpoints within 5% of pre-migration latency
- API contracts unchanged for all four contexts
- Database schemas unchanged for all four contexts
- Single JAR artifact builds successfully: `mvn clean package`

---

## Running Multiple Contexts Simultaneously

During the migration, it is possible to run some bounded contexts in the monolith while others remain as standalone microservices. The key constraint is that inter-context communication must be consistent:

- **Monolith contexts** communicate via the internal event bus (in-process, same transaction)
- **Standalone microservice contexts** communicate via HTTP/gRPC

If Preference is in the monolith but Segment is still a microservice, the `PreferenceCreatedEvent` will not reach Segment automatically. In this case, either:
1. Keep the HTTP call from Preference to Segment active during the transition period, or
2. Migrate Segment immediately after Preference (recommended — this is why Phase 2 follows Phase 1)

The recommended approach is to migrate Preference and Segment together in a single deployment window to avoid this split-brain scenario.

---

## Risk Mitigation Strategies

### Risk: Domain invariant regression
**Mitigation:** Property-based tests in domain modules run on every build. These tests generate hundreds of random inputs and verify invariants hold. Any regression is caught before deployment.

### Risk: API contract breakage
**Mitigation:** API contract tests compare request/response schemas before and after migration. These run as part of the integration test suite. A contract mismatch fails the build.

### Risk: Database schema divergence
**Mitigation:** Flyway migration scripts are reviewed before each phase. Schema validation tests (`@DataJpaTest`) verify entity mappings match the actual schema. No schema changes are permitted during migration.

### Risk: Performance degradation
**Mitigation:** Performance baseline tests measure p50, p95, p99 latency and throughput before and after each phase. A > 5% degradation triggers investigation before proceeding.

### Risk: Transaction boundary issues
**Mitigation:** The `TransactionConfiguration` applies transactions externally to use cases. Integration tests verify commit and rollback behavior. The event bus uses `@TransactionalEventListener` to ensure events are only delivered after the transaction commits.

### Risk: Silent event bus failures
**Mitigation:** Event subscribers log failures. Integration tests verify end-to-end event delivery. Monitoring alerts on segment evaluation rate drops after Preference creation.

### Risk: Partial migration state after rollback
**Mitigation:** Each phase has a clear rollback procedure. Database records written during the monolith deployment are schema-compatible with the original microservice. Rollback is tested in a staging environment before production migration.

---

## Validation Checklist (Per Phase)

Run these checks at the end of each phase before proceeding:

```
[ ] mvn clean verify passes (all tests green)
[ ] Domain tests run without Spring context
[ ] Domain tests complete in < 100ms per class
[ ] Integration tests pass without modification
[ ] API contract tests pass (no schema changes)
[ ] Database schema unchanged (Flyway diff = empty)
[ ] p99 latency within 5% of baseline
[ ] Mapper performance under 1ms per entity
[ ] Maven enforcer: no framework deps in domain/application modules
[ ] Single JAR builds and starts successfully
[ ] Smoke tests pass against running application
```
