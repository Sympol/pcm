# GDPR Compliance and Security Documentation

This document covers PCM's approach to GDPR compliance, the Data Protection Impact
Assessment (DPIA) summary, legal basis for processing, data retention policy, and
breach notification procedure.

---

## 1. GDPR Status of Encrypted PII

### 1.1 Encrypted PII is still PII

Under **GDPR Article 4(1)**, encrypted personal data remains personal data. PCM's
encryption does not anonymise data — it pseudonymises it. The original data can be
recovered using the encryption key.

Operators must continue to apply all GDPR obligations (lawful basis, data subject
rights, retention limits) to encrypted fields.

### 1.2 Pseudonymisation

PCM's field-level encryption constitutes **pseudonymisation** under **GDPR Article 4(5)**.
Pseudonymised data that cannot be attributed to a specific individual without the
encryption key is subject to reduced risk under GDPR, but is not exempt from it.

The separation of encrypted data (database) from key material (KMS/HSM) is the
technical measure that achieves pseudonymisation. A database breach without access
to the KMS does not expose readable PII.

### 1.3 Legal basis for processing

PCM processes PII under the following legal bases (**GDPR Article 6**):

| Processing activity | Legal basis |
|--------------------|-------------|
| Storing profile data (handle) | Legitimate interest / contract performance |
| Storing consent records | Legal obligation (ePrivacy, GDPR Art. 7) |
| Storing segment membership | Legitimate interest |
| Storing preference data | Contract performance / consent |

Operators must document their specific legal basis in their own privacy notices and
records of processing activities (RoPA).

---

## 2. PII Classification

PCM classifies PII into four categories that determine encryption requirements:

| Category | Examples | Encryption |
|----------|----------|------------|
| Standard PII | Email, phone number, name, handle | AES-256-GCM (mandatory) |
| Sensitive PII | Health data, biometric data | AES-256-GCM (mandatory) |
| Quasi-identifier | IP address, user agent | AES-256-GCM (mandatory) |
| Behavioural data | Browsing history, preferences | AES-256-GCM (mandatory) |

All four categories are encrypted before storage. Non-PII fields (e.g., tenant ID,
timestamps) are stored in plaintext and remain searchable.

Logs containing IP addresses are classified as PII and subject to the same encryption
requirements.

---

## 3. Data Protection Impact Assessment (DPIA)

### 3.1 Processing description

PCM processes PII on behalf of operators to manage user profiles, consent records,
audience segments, and communication preferences. PII is encrypted at rest using
AES-256-GCM with envelope encryption (KEK/DEK pattern).

### 3.2 Necessity and proportionality

- Encryption is necessary to protect data subjects from harm in the event of a
  database breach.
- Field-level encryption (rather than full-database encryption) is proportionate —
  it encrypts only PII fields, leaving non-sensitive data searchable.
- Blind indexing enables exact-match search without decrypting data, minimising
  unnecessary decryption operations.

### 3.3 Risks identified and mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Database breach exposes PII | Medium | High | AES-256-GCM encryption; ciphertext only in DB |
| KMS compromise exposes DEKs | Low | High | KEK/DEK separation; KEKs never leave KMS |
| Key loss makes data unrecoverable | Low | High | Offline KEK backup; key version history |
| IV reuse weakens encryption | Very low | High | Counter-based IV with overflow detection |
| Frequency analysis on blind indexes | Low | Medium | Global + per-record salts in HMAC |
| Insider threat (key access) | Low | High | RBAC; no direct human key access; audit logs |
| KMS outage prevents new writes | Medium | Medium | Circuit breaker; read-only mode; failover |

### 3.4 Residual risk

After mitigations, residual risk is assessed as **low**. The primary residual risk is
simultaneous loss of both the database backup and the KMS, which would result in
permanent data loss. This is mitigated by offline KEK backups stored separately from
the KMS.

---

## 4. Data Retention Policy

| Data type | Minimum retention | Maximum retention | Deletion mechanism |
|-----------|------------------|-------------------|--------------------|
| Encrypted PII (database) | Duration of service | Per operator policy | Cryptographic erasure (DEK deletion) |
| Audit logs | 1 year | 7 years (compliance-critical) | Secure deletion after retention period |
| Key version history | Duration of backup retention | — | Deleted with associated backups |
| Incident reports | 7 years | — | Secure deletion |
| Deletion certificates | 7 years | — | Secure deletion |

### Cryptographic erasure

When a user exercises their **right to erasure** (GDPR Article 17), PCM deletes the
user-specific DEK within 30 days. This renders all data encrypted with that DEK
permanently unreadable without modifying the database records.

The process:
1. `IKeyManager.deleteUserDEK(userId, context)` is called for each bounded context.
2. The DEK is deleted from KMS and evicted from the in-memory cache.
3. A **deletion certificate** is generated containing: deletion timestamp, key ID,
   user ID (hashed), and a cryptographic signature.
4. The deletion certificate is retained for 7 years as proof of erasure.
5. The audit trail records the deletion request and completion.

Operators must verify that no plaintext copies of the user's data exist outside PCM
(e.g., in application logs, analytics pipelines, or third-party systems).

---

## 5. Breach Notification Procedure

### 5.1 GDPR obligations

Under **GDPR Article 33**, a personal data breach must be notified to the competent
supervisory authority within **72 hours** of becoming aware of it, unless the breach
is unlikely to result in a risk to individuals.

Under **GDPR Article 34**, if the breach is likely to result in a high risk to
individuals, those individuals must be notified without undue delay.

### 5.2 Assessing breach impact

PCM's encryption significantly reduces breach impact:

- If only the **database** is compromised (no KMS access): data is ciphertext only.
  The breach is unlikely to result in a risk to individuals. Document this assessment.
- If the **KMS** is also compromised: DEKs may be exposed. Treat as a high-risk breach.
  Follow the [Key Compromise](../operations/incident-response.md#1-key-compromise)
  procedure immediately.
- If **audit logs** are accessed: the logs contain no plaintext PII or key material,
  but the access itself must be logged and investigated.

### 5.3 Notification content (GDPR Article 33(3))

Prepare a notification containing:

1. Nature of the breach and categories of personal data affected.
2. Approximate number of data subjects and records affected.
3. Name and contact details of the Data Protection Officer.
4. Likely consequences of the breach.
5. Measures taken or proposed to address the breach and mitigate its effects.

PCM's audit trail and incident reports provide the evidence needed to populate items
1, 2, 4, and 5.

### 5.4 Internal escalation

1. **0–1 hour**: Detect and contain. Revoke compromised keys. Preserve forensic evidence.
2. **1–4 hours**: Assess scope using `IKeyCompromiseHandler.identifyAffectedData()`.
3. **4–24 hours**: Notify DPO and legal team. Begin supervisory authority notification
   if required.
4. **24–72 hours**: Submit supervisory authority notification. Notify affected
   individuals if high risk.
5. **Post-incident**: Generate incident report. Conduct post-mortem. Update threat model.

---

## 6. Roles and Separation of Duties

| Role | Permissions | Cannot |
|------|-------------|--------|
| `Crypto_Admin` | Configure KMS policies | Rotate keys |
| `Key_Operator` | Rotate keys, manage key lifecycle | Modify KMS policies |
| `Auditor` | Read audit logs and key metadata | Write operations |
| `Developer` | Use encryption services | Manage keys |

No single role has full access to all cryptographic operations. Break-glass procedures
require **dual authorisation** from two personnel with appropriate roles.

Direct human access to encryption keys is prohibited. All key operations are performed
by machine identities authenticated via IAM, with every access logged.

---

## 7. Compliance Audit Support

PCM provides the following artefacts for regulatory audits:

| Artefact | Location | Retention |
|----------|----------|-----------|
| Encryption architecture documentation | `docs/architecture/pii-encryption.md` | Indefinite |
| DPIA summary | This document, §3 | 7 years |
| Audit logs (encrypted, signed) | Audit log store | 1–7 years |
| Key rotation logs | Audit log store (CRITICAL level) | 7 years |
| Deletion certificates | Secure storage | 7 years |
| Incident reports | Secure storage | 7 years |
| Penetration test reports | Security team | 3 years |

Annual penetration testing of the encryption implementation is required, including
cryptographic implementation review, side-channel attack testing, and timing attack
analysis.
