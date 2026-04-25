# PCM Encryption Operations Runbook

This runbook covers day-to-day and emergency operational procedures for the PCM
encryption subsystem. It is intended for platform engineers and on-call operators.

For security incident response (key compromise, data breach, KMS outage) see
[incident-response.md](incident-response.md).

**Quick reference**

| Task | Section |
|------|---------|
| Rotate a DEK manually | [§1.2](#12-manual-dek-rotation) |
| Emergency key rotation | [§1.3](#13-emergency-dek-rotation-key-compromise) |
| Rotate a KEK | [§1.4](#14-kek-rotation) |
| Restore from backup | [§2.2](#22-restoring-from-backup) |
| Respond to an alert | [§3.2](#32-alert-response) |
| Deploy to a new environment | [§4.1](#41-pre-deployment-checklist) |
| First-time KMS setup | [§4.2](#42-first-time-kms-initialisation) |
| Troubleshoot decryption errors | [§5](#5-troubleshooting) |
| Disaster recovery | [§6](#6-disaster-recovery) |

---

## 1. Key Rotation

### 1.1 Scheduled DEK rotation

DEKs rotate automatically when any of the following thresholds are reached:

| Trigger | Threshold |
|---------|-----------|
| Age | 90 days since creation |
| Volume | 1 TB of data encrypted |
| Operations | 2³² encryption operations |
| IV counter | Approaching 2³¹ (automatic pre-emptive rotation) |

No manual action is required for scheduled rotation. Monitor the
`pcm.encryption.key_rotation_compliance` metric to confirm rotations are completing
on schedule. Alert threshold: any key overdue by more than 7 days.

### 1.2 Manual DEK rotation

To rotate a DEK immediately (e.g., ahead of schedule or after a suspected exposure):

1. Identify the bounded context: `PROFILE`, `CONSENT`, `SEGMENT`, or `PREFERENCE`.
2. Call `IKeyManager.rotateDEK(context)` via the admin API or management endpoint.
3. Confirm the new DEK ID is logged in the audit trail at `CRITICAL` level.
4. Verify the old DEK is marked `ROTATED` in KMS metadata.
5. Confirm the DEK cache is invalidated (the old key is evicted within 60 seconds).

Data encrypted before rotation remains decryptable — the old DEK is retained in KMS
and identified by the `key_id` embedded in each ciphertext.

### 1.3 Emergency DEK rotation (key compromise)

Target: complete within **15 minutes** of detection.

Follow the [Key Compromise](incident-response.md#1-key-compromise) procedure in the
incident response guide. Emergency rotation is triggered via
`IKeyCompromiseHandler.revokeKey(keyId)` followed by
`IKeyCompromiseHandler.reEncryptWithNewKey(compromisedKeyId, context)`.

### 1.4 KEK rotation

KEKs rotate annually or when required by compliance policy.

1. Call `IKeyManager.rotateKEK(context)` for each affected bounded context.
2. The `KeyManager` re-encrypts all DEKs for the context with the new KEK.
3. All cached DEKs for the context are invalidated.
4. Confirm the rotation event is logged at `CRITICAL` level.
5. Verify decryption of a sample of existing records succeeds after rotation.

KEK rotation is independent of DEK rotation and does not require re-encrypting
application data.

---

## 2. Backup and Restore

### 2.1 What is backed up

| Artifact | Content | Encryption |
|----------|---------|------------|
| Database backup | Ciphertext only — no plaintext PII | Encrypted at rest by database |
| KEK export | KEKs encrypted with offline master key | Offline master key in HSM/secure offline storage |
| Key version history | Mapping of key IDs to rotation timestamps | Encrypted backup metadata |
| Audit logs | Append-only, encrypted and signed | Separate audit log encryption key |

Plaintext PII is **never** present in any backup artifact.

### 2.2 Restoring from backup

1. Identify the restore point (timestamp).
2. Determine which key versions were active at that timestamp using the key version
   history mapping.
3. Verify those key versions are available in KMS (or restore from KEK export if
   the KMS was also lost).
4. Restore the database backup (ciphertext).
5. Validate decryption by sampling a representative set of records.
6. Confirm the audit trail is intact and continuous up to the restore point.

### 2.3 Point-in-time recovery

PCM supports point-in-time recovery because every ciphertext embeds the `key_id` of
the DEK used to encrypt it. As long as the corresponding DEK (and its KEK) are
available, any historical backup can be decrypted.

Key version history must be preserved for the full backup retention period. Do not
delete rotated DEKs from KMS until all backups that reference them have expired.

### 2.4 Backup validation

Test backup restoration quarterly:

1. Restore a recent backup to an isolated environment.
2. Verify the correct key versions are available.
3. Decrypt a sample of records and confirm plaintext matches expected values.
4. Document the test result and any issues found.

---

## 3. Monitoring and Alerting

### 3.1 Key metrics

| Metric | Target | Alert threshold |
|--------|--------|-----------------|
| `pcm.encryption.coverage_pct` | 100% | < 95% |
| `pcm.encryption.key_rotation_compliance_pct` | 100% | Any key > 7 days overdue |
| `pcm.encryption.failed_decryptions_per_min` | 0 | > 10/min for 5 min |
| `pcm.encryption.kms_availability_pct` | 99.9% | Any unavailability > 2 min |
| `pcm.encryption.latency_p95_ms` | < 10 ms | > 50 ms for 5 min |
| `pcm.encryption.dek_cache_hit_rate` | > 90% | < 80% |

### 3.2 Alert response

**Encryption coverage drops below 95%**
- Check for new PII fields added without `@EncryptedField` annotation.
- Review recent deployments for missing entity listener configuration.

**Key rotation overdue**
- Check KMS connectivity and permissions.
- Trigger manual rotation if automatic rotation has stalled.

**Failed decryptions spike**
- Check for ciphertext corruption in the database.
- Check for key version mismatches (e.g., after a failed rotation).
- Investigate for tampering — a sustained spike may indicate an attack.

**KMS unavailable**
- PCM enters read-only mode automatically (decryption with cached DEKs continues).
- New encryption operations are rejected.
- Follow the [KMS Outage](incident-response.md#3-kms-outage) procedure.

**Latency degradation**
- Check DEK cache hit rate — a low hit rate causes extra KMS round-trips.
- Check KMS latency independently.
- Check for GC pressure or resource contention on the application host.

### 3.3 Audit log monitoring

The audit logger monitors for suspicious search patterns:

- More than **1 000 queries per hour** against encrypted fields triggers a security alert.
- More than **100 queries per minute per service** triggers rate limiting.

Review `SECURITY_EVENT` audit entries daily. Unexplained spikes in decryption volume
or environment mismatch events require immediate investigation.

---

## 4. Deployment Procedures

### 4.1 Pre-deployment checklist

- [ ] KMS connectivity verified from the target environment.
- [ ] KEKs initialised for all four bounded contexts in the target environment.
- [ ] Blind index key initialised in KMS.
- [ ] `pcm.encryption.environment` property matches the target environment
      (`DEV`, `STAGING`, or `PROD`).
- [ ] mTLS certificates provisioned (PROD and STAGING).
- [ ] `pcm.encryption.blind-index-global-salt` set to a secret value (not the test default).
- [ ] Audit log storage configured with append-only access.
- [ ] Monitoring dashboards and alert rules deployed.

### 4.2 First-time KMS initialisation

On first deployment to a new environment:

1. Create the KMS namespace for the environment.
2. Call `KeyManager.initializeKEK(context)` for each bounded context.
3. Call `KeyManager.initializeBlindIndexKey()`.
4. Verify KEK IDs are logged and stored in application configuration.
5. Run the deployment smoke test to confirm encryption/decryption round-trips succeed.

### 4.3 Rolling deployments

PCM supports rolling deployments without downtime because:

- Ciphertexts are self-describing (version, algorithm, key ID are embedded).
- Old and new application versions can coexist and decrypt each other's ciphertexts.
- DEK cache TTL (1 hour) means new instances warm up quickly.

### 4.4 Configuration reference

See [Developer Guide — Configuration](../developer-guide/encryption.md#3-configuration-reference)
for the full `application.yml` property reference.

---

## 5. Troubleshooting

### Decryption fails with `INVALID_CIPHERTEXT_FORMAT`

The stored value is not a valid PCM ciphertext. Possible causes:
- The field was populated before encryption was enabled (plaintext stored in an
  encrypted column).
- Data corruption in the database.
- The column was written by a different application.

Resolution: identify the affected records, determine whether the original plaintext
is recoverable, and re-encrypt.

### Decryption fails with `TAMPERING_DETECTED`

The authentication tag verification failed. The ciphertext has been modified after
encryption. This is a security event — escalate immediately and follow the
[Data Breach](incident-response.md#2-data-breach) procedure.

### Decryption fails with `KEY_NOT_FOUND`

The DEK identified by `key_id` in the ciphertext is not available in KMS. Possible causes:
- The DEK was deleted prematurely (before all referencing backups expired).
- KMS namespace misconfiguration.
- The ciphertext was moved from a different environment.

Resolution: restore the DEK from backup, or — if the data is from a different
environment — reject it (environment mismatch is a security violation).

### `KEY_UNAVAILABLE` errors on new writes

KMS is unreachable. PCM is in read-only mode. Follow the
[KMS Outage](incident-response.md#3-kms-outage) procedure.

### High KMS latency / low DEK cache hit rate

- Increase `pcm.encryption.dek-cache.max-size` if the number of active DEKs exceeds
  the cache limit.
- Check for cache invalidation storms (e.g., rapid successive rotations).
- Verify the application has sufficient heap for the cache.

---

## 6. Disaster Recovery

### Scenario: KMS permanently lost

1. Restore KEKs from the offline master key backup (stored in HSM or secure offline
   storage).
2. Re-import KEKs into the new KMS instance.
3. Verify DEK decryption works with the restored KEKs.
4. Update `pcm.encryption.kms.endpoint` to point to the new KMS.
5. Restart the application — the DEK cache will warm up on first access.

### Scenario: Database lost, KMS intact

1. Restore the database from the most recent backup (ciphertext only).
2. Identify the key versions active at the backup timestamp.
3. Verify those DEKs are available in KMS.
4. Validate decryption of a sample of records.
5. Resume normal operations.

### Scenario: Both database and KMS lost

This is the worst-case scenario. Data recovery is only possible if:
- The offline KEK backup is available.
- The database backup is available.

Follow both recovery procedures above in sequence. If the offline KEK backup is also
lost, the data is unrecoverable by design (cryptographic erasure).

Document the incident and review backup procedures to prevent recurrence.
