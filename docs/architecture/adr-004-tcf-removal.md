# ADR 004: Remove IAB TCF from PCM Core

## Status
Accepted — Implemented (April 2026)

## Context
PCM is a privacy-first platform designed to help organizations regain control over user data management in a secure and transparent way. The IAB Transparency & Consent Framework (TCF) is an advertising-industry standard whose primary purpose is to legitimize large-scale tracking by hundreds of advertising vendors. This is fundamentally at odds with PCM's mission.

The Belgian Data Protection Authority (APD) ruled in 2022 that TCF 2.0 does not satisfy GDPR requirements as designed, citing that the legal bases relied upon by the TCF (legitimate interest and consent) were not validly established. This ruling reinforces the incompatibility between TCF and a genuinely privacy-first platform.

Keeping TCF as a built-in feature of PCM sends a contradictory signal: a platform that claims to protect user privacy while simultaneously providing first-class support for a framework ruled non-compliant with the very regulation it claims to implement.

## Decision
Remove all TCF-specific code from PCM core:

- Delete `TCString`, `VendorId`, `PurposeId` value objects from `consent-domain`
- Delete `TCFValidationException` from `consent-domain`
- Delete `ProcessTCFConsentUseCase` and `TCFConsentRequest` from `consent-application`
- Remove the `processTCFConsentUseCase` Spring bean from `ConsentUseCaseConfiguration`
- Remove the `POST /api/v1/consents/tcf` endpoint from `ConsentController`
- Remove the `handleTCFValidation` exception handler from `GlobalExceptionHandler`
- Archive the `iab-tcf-cmp-integration` spec to `.kiro/specs/archive/`

TCF support will be proposed as a separate external module (`pcm-tcf-adapter`) for organizations that specifically need it. This module will depend on PCM as a library and implement TCF processing by translating TC Strings into generic PCM consent operations — following the same adapter pattern already established in PCM's architecture.

## Implementation

This decision was implemented in full as part of the `tcf-removal` spec (15 tasks, all completed April 2026).

### Files deleted
| File | Reason |
|------|--------|
| `consent-domain/.../model/TCString.java` | IAB TC String value object — purely TCF concept |
| `consent-domain/.../model/VendorId.java` | IAB vendor identifier — purely TCF concept |
| `consent-domain/.../model/PurposeId.java` | IAB purpose identifier — purely TCF concept |
| `consent-domain/.../exception/TCFValidationException.java` | TCF-specific exception |
| `consent-application/.../usecase/ProcessTCFConsentUseCase.java` | TCF use case |
| `consent-application/.../dto/TCFConsentRequest.java` | TCF request DTO |
| `consent-application/.../usecase/ProcessTCFConsentUseCaseTest.java` | Tests for deleted use case |
| `pcm-infrastructure-spring/.../consent/ConsentTCFIntegrationTest.java` | Integration tests for deleted endpoint |

### Files refactored
| File | Change |
|------|--------|
| `ConsentUseCaseConfiguration.java` | Removed `processTCFConsentUseCase()` bean |
| `ConsentController.java` | Removed `POST /api/v1/consents/tcf` endpoint and `ProcessTCFConsentUseCase` injection |
| `GlobalExceptionHandler.java` | Removed `handleTCFValidation()` handler |
| `ConsentApiContractTest.java` | Removed `tcf_correctPathAndStatusCode()` and `tcf_shortTcString_returns4xx()` test methods |

## Consequences

### Positive
- **Endpoint removed**: `POST /api/v1/consents/tcf` is no longer available in PCM core. The `consent-context` now exposes exactly four clean GDPR endpoints: `POST /api/v1/consents`, `DELETE /api/v1/consents/{id}`, `GET /api/v1/consents/verify`, `GET /api/v1/consents/history`.
- **No database migration required**: `ConsentJpaEntity` had no TCF-specific columns; `purpose` and `scope` are generic strings that remain unchanged.
- **Clean bounded context**: `consent-context` is now a pure, generic GDPR consent management bounded context with no advertising-industry dependencies. All 30 module tests (7 domain + 20 application + 3 infrastructure) pass independently.
- **Stronger positioning**: PCM's identity as a privacy-first platform is reinforced by removing a framework ruled non-compliant with GDPR.
- **Extensibility preserved**: Organizations that need TCF compliance can adopt `pcm-tcf-adapter` as an external module without modifying PCM core.
- **Deadline risk eliminated**: The TCF 2.3 upgrade deadline (February 2026) is no longer a concern for the PCM core codebase.

### Negative
- Organizations that currently rely on `POST /api/v1/consents/tcf` must migrate to `pcm-tcf-adapter` once it is available.
- `pcm-tcf-adapter` is not yet implemented — organizations with an immediate TCF requirement cannot use PCM core as a drop-in replacement today.

## Related ADRs
- [ADR-001: Hexagonal Architecture](adr-001-hexagonal-architecture.md) — the adapter pattern that makes `pcm-tcf-adapter` possible
- [ADR-003: Infrastructure Abstraction](adr-003-infrastructure-abstraction.md) — how external modules integrate with PCM
