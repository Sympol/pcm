# Incident Response

PCM maintains documented internal procedures for responding to security incidents affecting
personal data and encryption infrastructure. These procedures are reviewed and updated regularly.

## Covered Incident Types

**Encryption key compromise** — Suspected or confirmed exposure of a data encryption key (DEK)
or key encryption key (KEK). The system supports immediate key revocation, affected data
identification, re-encryption with a new key, and generation of a formal incident report.

**Data breach** — Unauthorized access to personal data, whether encrypted or in transit.
Response includes containment, forensic preservation, scope assessment, and GDPR notification
obligations (72-hour supervisory authority notification where applicable).

**Key management system (KMS) outage** — Unavailability of the key management infrastructure.
The system is designed to degrade gracefully and resume normal operations upon recovery.

## Principles

- All incident response actions are logged to an append-only audit trail.
- Incident reports never contain plaintext PII or key material.
- Key compromise response targets containment within 15 minutes of detection.
- GDPR Article 33 notification obligations are tracked and enforced.

## Reporting a Security Issue

To report a vulnerability or suspected incident, please follow the process described in
[SECURITY.md](SECURITY.md).

For operators deploying PCM, a detailed guide covering key compromise response, data breach
handling, KMS outage procedures, and GDPR notification obligations is available in
[docs/operations/incident-response.md](docs/operations/incident-response.md).
