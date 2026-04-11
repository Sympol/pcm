package dev.vibeafrika.pcm.domain.encryption;

/**
 * Domain interface for audit logging of encryption operations.
 * 
 * <p>The AuditLogger is responsible for:
 * <ul>
 *   <li>Logging all encryption and decryption operations with context and metadata</li>
 *   <li>Logging key rotation events with old and new key identifiers</li>
 *   <li>Logging security events (tampering detected, unauthorized access, etc.)</li>
 *   <li>Logging key access operations for audit trail</li>
 *   <li>Excluding plaintext PII data and encryption keys from logs</li>
 *   <li>Encrypting audit logs at rest using a separate audit log encryption key</li>
 *   <li>Signing audit log entries to ensure integrity</li>
 *   <li>Implementing append-only log storage to prevent tampering</li>
 * </ul>
 * 
 * <p>Audit log entries should contain:
 * <ul>
 *   <li>Timestamp in ISO8601 format</li>
 *   <li>Event type (encryption, decryption, key rotation, security event, key access)</li>
 *   <li>Log level (CRITICAL, HIGH, MEDIUM, LOW)</li>
 *   <li>Bounded context where the event occurred</li>
 *   <li>Service identity performing the operation</li>
 *   <li>User context (if applicable)</li>
 *   <li>Key ID involved (if applicable)</li>
 *   <li>Field identifier (but NOT the plaintext value)</li>
 *   <li>Success status</li>
 *   <li>Error code (if operation failed)</li>
 *   <li>Additional metadata</li>
 *   <li>HMAC signature for integrity verification</li>
 * </ul>
 * 
 * <p>Security requirements:
 * <ul>
 *   <li>NEVER log plaintext PII data</li>
 *   <li>NEVER log encryption keys or key material</li>
 *   <li>Always encrypt audit logs at rest</li>
 *   <li>Always sign audit log entries with HMAC</li>
 *   <li>Implement append-only storage (no modifications or deletions)</li>
 *   <li>Log all audit log access operations</li>
 * </ul>
 * 
 */
public interface IAuditLogger {

    /**
     * Logs an encryption operation with context and metadata.
     * 
     * <p>This method records when PII data is encrypted, including:
     * <ul>
     *   <li>Timestamp of the encryption operation</li>
     *   <li>Bounded context where encryption occurred</li>
     *   <li>Service identity performing the encryption</li>
     *   <li>Key ID used for encryption</li>
     *   <li>Field identifier (but NOT the plaintext value)</li>
     *   <li>Success status</li>
     *   <li>Error code if operation failed</li>
     * </ul>
     * 
     * <p>The audit log entry MUST NOT contain:
     * <ul>
     *   <li>Plaintext PII data</li>
     *   <li>Encryption keys or key material</li>
     * </ul>
     * 
     * @param event the encryption event containing operation metadata
     * @return Result containing void on success, or AuditError if logging fails
     */
    Result<Void, AuditError> logEncryption(EncryptionEvent event);

    /**
     * Logs a decryption operation with context and metadata.
     * 
     * <p>This method records when PII data is decrypted, including:
     * <ul>
     *   <li>Timestamp of the decryption operation</li>
     *   <li>Bounded context where decryption occurred</li>
     *   <li>Service identity performing the decryption</li>
     *   <li>Key ID used for decryption</li>
     *   <li>Field identifier (but NOT the plaintext value)</li>
     *   <li>Success status</li>
     *   <li>Error code if operation failed</li>
     * </ul>
     * 
     * <p>The audit log entry MUST NOT contain:
     * <ul>
     *   <li>Plaintext PII data</li>
     *   <li>Encryption keys or key material</li>
     * </ul>
     * 
     * @param event the decryption event containing operation metadata
     * @return Result containing void on success, or AuditError if logging fails
     */
    Result<Void, AuditError> logDecryption(DecryptionEvent event);

    /**
     * Logs a key rotation event.
     * 
     * <p>This method records when encryption keys are rotated, including:
     * <ul>
     *   <li>Timestamp of the rotation</li>
     *   <li>Bounded context where rotation occurred</li>
     *   <li>Service identity performing the rotation</li>
     *   <li>Old key ID being rotated</li>
     *   <li>New key ID replacing the old key</li>
     *   <li>Key type (DEK or KEK)</li>
     *   <li>Rotation reason (scheduled, emergency, compliance, etc.)</li>
     *   <li>Success status</li>
     *   <li>Error code if operation failed</li>
     * </ul>
     * 
     * <p>Key rotation events are logged at CRITICAL level regardless of
     * configured audit logging level.
     * 
     * @param event the key rotation event containing rotation metadata
     * @return Result containing void on success, or AuditError if logging fails
     */
    Result<Void, AuditError> logKeyRotation(KeyRotationEvent event);

    /**
     * Logs a security event (tampering detected, unauthorized access, etc.).
     * 
     * <p>This method records security-related incidents, including:
     * <ul>
     *   <li>Timestamp of the event</li>
     *   <li>Bounded context where the event occurred</li>
     *   <li>Service identity involved in the event</li>
     *   <li>Event type (tampering detected, unauthorized access, environment mismatch, etc.)</li>
     *   <li>Severity level (CRITICAL, HIGH, MEDIUM, LOW)</li>
     *   <li>Key ID involved (if applicable)</li>
     *   <li>Field identifier (if applicable)</li>
     *   <li>Description of the security event</li>
     * </ul>
     * 
     * <p>Security events include:
     * <ul>
     *   <li>Tampering detection (authentication tag verification failure)</li>
     *   <li>Unauthorized key access attempts</li>
     *   <li>Environment mismatch (key from wrong environment)</li>
     *   <li>Key compromise suspicion</li>
     *   <li>Mass query patterns against encrypted fields</li>
     *   <li>Counter overflow imminent</li>
     * </ul>
     * 
     * <p>Security events are logged at HIGH or CRITICAL level depending on severity.
     * 
     * @param event the security event containing incident metadata
     * @return Result containing void on success, or AuditError if logging fails
     */
    Result<Void, AuditError> logSecurityEvent(SecurityEvent event);

    /**
     * Logs key access for audit trail.
     * 
     * <p>This method records when encryption keys are accessed, including:
     * <ul>
     *   <li>Timestamp of the access</li>
     *   <li>Bounded context where access occurred</li>
     *   <li>Service identity accessing the key</li>
     *   <li>Key ID being accessed</li>
     *   <li>Key type (DEK or KEK)</li>
     *   <li>Access type (retrieve, cache_hit, cache_miss, etc.)</li>
     *   <li>Success status</li>
     *   <li>Error code if operation failed</li>
     * </ul>
     * 
     * <p>Key access logging enables:
     * <ul>
     *   <li>Tracking which services access which keys</li>
     *   <li>Detecting unauthorized key access attempts</li>
     *   <li>Monitoring key usage patterns</li>
     *   <li>Compliance auditing</li>
     * </ul>
     * 
     * @param event the key access event containing access metadata
     * @return Result containing void on success, or AuditError if logging fails
     */
    Result<Void, AuditError> logKeyAccess(KeyAccessEvent event);

    /**
     * Logs an audit log access operation.
     *
     * <p>This method records when audit logs are read or accessed, including:
     * <ul>
     *   <li>Timestamp of the access</li>
     *   <li>Bounded context where access occurred</li>
     *   <li>Service identity of the system performing the access</li>
     *   <li>Accessor identity (who accessed the audit logs)</li>
     *   <li>Description of what was accessed</li>
     *   <li>Success status</li>
     *   <li>Error code if operation failed</li>
     * </ul>
     *
     * <p>WHEN audit log access occurs, THE Audit_Logger SHALL
     * log the access event with accessor identity and timestamp.
     *
     * @param event the audit log access event containing accessor identity and metadata
     * @return Result containing void on success, or AuditError if logging fails
     */
    Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event);
}
