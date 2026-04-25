# Incident Response Guide for PCM Operators

This guide is intended for teams operating a PCM deployment. It describes how to use
PCM's built-in incident response capabilities to handle security events affecting
encrypted PII data.

PCM provides the `IKeyCompromiseHandler` interface and its default implementation
`KeyCompromiseHandler` to support structured incident response. All actions taken
through this interface are automatically logged to the append-only audit trail.

---

## 1. Key Compromise

A key compromise occurs when a Data Encryption Key (DEK) or Key Encryption Key (KEK)
is suspected or confirmed to have been exposed.

### Detection signals

- Anomalous key access patterns in audit logs
- External threat intelligence indicating key material exposure
- Unauthorized access to KMS credentials
- Automated monitoring alerts (unusual decryption volume, environment mismatch)

### Response steps

**Step 1 — Revoke the compromised key immediately**

Call `IKeyCompromiseHandler.revokeKey(keyId)`. This invalidates the key from the
in-memory DEK cache and logs a `KEY_COMPROMISED` CRITICAL security event to the
audit trail. Target: within 15 minutes of detection.

**Step 2 — Identify affected data**

Call `IKeyCompromiseHandler.identifyAffectedData(keyId)`. This returns the list of
field/record identifiers that were encrypted with the compromised key. Use this to
scope the incident and communicate impact.

**Step 3 — Re-encrypt with a new key**

Call `IKeyCompromiseHandler.reEncryptWithNewKey(compromisedKeyId, context)` for each
affected bounded context (`PROFILE`, `CONSENT`, `SEGMENT`, `PREFERENCE`). This
triggers DEK rotation and re-encrypts all identified records with the new key.
A `DATA_RE_ENCRYPTED` HIGH security event is logged with the new key ID.

If the KEK was also compromised, additionally call `IKeyManager.rotateKEK(context)`
for each affected context.

**Step 4 — Generate an incident report**

Call `IKeyCompromiseHandler.generateIncidentReport(keyId, description)`. The returned
`IncidentReport` contains the incident ID, timestamp, affected data scope, actions
taken, and new key ID. It never contains plaintext PII or key material. Retain this
report for compliance audits.

**Step 5 — Post-incident**

- Verify all affected data has been re-encrypted by checking the `reEncryptedCount`
  in the incident report
- Review and update KMS access policies
- Schedule a post-mortem
- Update your threat model if a new attack vector was identified

---

## 2. Data Breach

A data breach is unauthorized access to personal data, whether encrypted or in transit.

### Response steps

1. Isolate the affected system or service — revoke credentials, block network access
2. Preserve forensic evidence — do not modify or delete logs
3. Notify your Data Protection Officer (DPO)
4. If encryption keys may have been exposed, follow the **Key Compromise** procedure above
5. Determine which bounded contexts and PII fields were exposed
6. Assess whether data was accessed in encrypted or plaintext form

### GDPR notification obligations

Under GDPR Article 33, if personal data was exposed you must notify the competent
supervisory authority **within 72 hours** of becoming aware of the breach. Prepare a
notification containing:

- Nature of the breach and categories of data affected
- Approximate number of data subjects affected
- Likely consequences of the breach
- Measures taken or proposed to address the breach

If the breach poses a high risk to data subjects, notify affected individuals without
undue delay (GDPR Article 34).

PCM's audit trail provides the evidence needed to scope the breach and demonstrate
the measures taken.

---

## 3. KMS Outage

A KMS outage occurs when the Key Management System is unavailable, preventing new
encryption operations.

### Behavior during outage

PCM's circuit breaker activates automatically on KMS health check failures:

- **Decryption** continues using cached DEKs (within their 1-hour TTL)
- **New encryption** is rejected with a `KEY_UNAVAILABLE` error
- Alerts are triggered after 2 minutes of sustained unavailability

Do not attempt to bypass encryption or use fallback keys during an outage.

### Recovery steps

1. Monitor KMS provider status and wait for restoration
2. Once KMS is restored, verify connectivity with a health check
3. The DEK cache will refresh automatically on the next encryption request
4. Review audit logs for operations that failed during the outage
5. Assess whether any data was left unencrypted due to the outage

---

## 4. Adapting this guide to your organization

This guide describes PCM's built-in capabilities. You should extend it with your
organization-specific information:

- **Escalation contacts** — security team, DPO, on-call engineer, KMS provider support
- **SLA targets** — your internal response time objectives
- **KMS provider details** — AWS KMS, Azure Key Vault, GCP Cloud KMS, or HashiCorp Vault
  specific procedures
- **Monitoring integration** — how PCM metrics and alerts feed into your SIEM or
  alerting platform
- **Post-mortem process** — your internal review and lessons-learned workflow

---

## Related

- `IKeyCompromiseHandler` — domain interface for incident response operations
- `KeyCompromiseHandler` — default Spring implementation
- `IncidentReport` — value object returned by `generateIncidentReport()`
- [SECURITY.md](../../SECURITY.md) — how to report a vulnerability in PCM itself
