package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Infrastructure implementation of {@link IAuditLogger} using SLF4J/Logback.
 *
 * <p>Produces structured JSON-like log entries for every encryption, decryption,
 * key-rotation, security, and key-access event. Each entry is:
 * <ol>
 *   <li>Signed with HMAC-SHA256 for integrity.</li>
 *   <li>Encrypted at rest via {@link AuditLogStore} using a dedicated AES-256-GCM
 *       key that is separate from the DEK/KEK hierarchy.</li>
 *   <li>Persisted in an append-only store that prohibits modification and deletion</li>
 * </ol>
 *
 * <p>Security guarantees:
 * <ul>
 *   <li>Plaintext PII data is NEVER included in any log entry.</li>
 *   <li>Encryption key material is NEVER included in any log entry.</li>
 *   <li>Every entry carries a timestamp, event type, bounded context, and
 *       service identity.</li>
 *   <li>Every entry is signed with HMAC-SHA256 for integrity verification.</li>
 *   <li>Every entry is encrypted at rest with AES-256-GCM.</li>
 * </ul>
 *
 * <p>Configurable log levels:
 * <ul>
 *   <li>{@link LogLevel#CRITICAL} – key rotation events; always logged</li>
 *   <li>{@link LogLevel#HIGH} – authentication failures</li>
 *   <li>{@link LogLevel#MEDIUM} – normal encryption/decryption operations</li>
 *   <li>{@link LogLevel#LOW} – verbose/diagnostic events (key cache hits, etc.)</li>
 * </ul>
 *
 * <p>Events below the configured minimum level are silently dropped, EXCEPT for
 * CRITICAL events which are always logged regardless of configuration (Req 21.4).
 *
 * <p>Sampling: for levels in {@link AuditConfiguration#getSampledLevels()},
 * only 1 in every N events is logged where N = {@link AuditConfiguration#getSamplingRate()}.
 *
 * <p>Access type distinction : log entries include an
 * {@code accessType} field ({@code SYSTEM} or {@code HUMAN}) when provided.
 *
 * <p>When an {@link AuditLogStore} is provided, every entry is also persisted to
 * the encrypted append-only store in addition to being written to the SLF4J log.
 * If no store is provided (e.g. in tests), only SLF4J logging is performed.
 */
public class AuditLogger implements IAuditLogger {

    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String ERROR_CODE_AUDIT_LOG_FAILED = "AUDIT_LOG_FAILED";

    /** Service identity reported in every log entry produced by this logger. */
    private final String serviceIdentity;

    /**
     * Secret key used to sign log entries with HMAC-SHA256.
     * Must be kept confidential; never logged.
     */
    private final byte[] signingKey;

    /**
     * Optional append-only encrypted store. When present, every log entry is
     * persisted as an encrypted, signed record in addition to SLF4J output.
     * May be {@code null} when running without a database (e.g. unit tests).
     */
    private final AuditLogStore auditLogStore;

    /**
     * Audit logging configuration controlling minimum level and sampling.
     * Defaults to {@link AuditConfiguration#defaults()} if not provided.
     */
    private final AuditConfiguration auditConfiguration;

    /**
     * Monotonically increasing counter used for sampling decisions.
     * Thread-safe via AtomicLong.
     */
    private final AtomicLong samplingCounter = new AtomicLong(0);

    /**
     * Creates an AuditLogger with a custom service identity and signing key.
     * Entries are written only to SLF4J (no persistent encrypted store).
     * Uses default {@link AuditConfiguration}.
     *
     * @param serviceIdentity human-readable name of the service (e.g. "pcm-service")
     * @param signingKey      secret bytes used for HMAC-SHA256 entry signing
     */
    public AuditLogger(String serviceIdentity, byte[] signingKey) {
        this(serviceIdentity, signingKey, null, AuditConfiguration.defaults());
    }

    /**
     * Creates an AuditLogger with encrypted, append-only persistent storage.
     * Uses default {@link AuditConfiguration}.
     *
     * @param serviceIdentity human-readable name of the service (e.g. "pcm-service")
     * @param signingKey      secret bytes used for HMAC-SHA256 entry signing
     * @param auditLogStore   append-only encrypted store; may be {@code null} to
     *                        disable persistent storage
     */
    public AuditLogger(String serviceIdentity, byte[] signingKey, AuditLogStore auditLogStore) {
        this(serviceIdentity, signingKey, auditLogStore, AuditConfiguration.defaults());
    }

    /**
     * Creates an AuditLogger with full configuration control.
     *
     * @param serviceIdentity    human-readable name of the service (e.g. "pcm-service")
     * @param signingKey         secret bytes used for HMAC-SHA256 entry signing
     * @param auditLogStore      append-only encrypted store; may be {@code null}
     * @param auditConfiguration configures minimum level and sampling behaviour
     */
    public AuditLogger(String serviceIdentity, byte[] signingKey,
                       AuditLogStore auditLogStore, AuditConfiguration auditConfiguration) {
        this.serviceIdentity = Objects.requireNonNull(serviceIdentity, "serviceIdentity cannot be null");
        this.signingKey = Objects.requireNonNull(signingKey, "signingKey cannot be null").clone();
        this.auditLogStore = auditLogStore; // nullable
        this.auditConfiguration = Objects.requireNonNull(auditConfiguration, "auditConfiguration cannot be null");
    }

    // -------------------------------------------------------------------------
    // Level filtering and sampling helpers
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} if an event at the given level should be logged,
     * taking into account the configured minimum level and sampling rate.
     *
     * <p>CRITICAL events are ALWAYS logged regardless of configuration.
     *
     * @param level the level of the event to evaluate
     * @return {@code true} if the event should be logged
     */
    boolean shouldLog(LogLevel level) {
        // CRITICAL is always logged 
        if (level == LogLevel.CRITICAL) {
            return true;
        }
        // Filter by minimum level
        if (!level.isAtLeast(auditConfiguration.getMinimumLevel())) {
            return false;
        }
        // Apply sampling for sampled levels
        if (auditConfiguration.getSampledLevels().contains(level)) {
            int rate = auditConfiguration.getSamplingRate();
            if (rate > 1) {
                long count = samplingCounter.incrementAndGet();
                return (count % rate) == 1; // log the 1st, (N+1)th, (2N+1)th, ...
            }
        }
        return true;
    }

    /**
     * Returns the {@link AuditConfiguration} used by this logger.
     */
    public AuditConfiguration getAuditConfiguration() {
        return auditConfiguration;
    }

    // -------------------------------------------------------------------------
    // IAuditLogger implementation
    // -------------------------------------------------------------------------

    @Override
    public Result<Void, AuditError> logEncryption(EncryptionEvent event) {
        Objects.requireNonNull(event, "EncryptionEvent cannot be null");
        try {
            // Encryption operations are MEDIUM level
            LogLevel level = LogLevel.MEDIUM;
            if (!shouldLog(level)) {
                return voidSuccess();
            }
            String entry = buildEncryptionEntry(event, level);
            if (event.isSuccess()) {
                log.info(entry);
            } else {
                log.warn(entry);
            }
            persistToStore("ENCRYPTION", event.getTimestamp(), entry);
            return voidSuccess();
        } catch (Exception e) {
            return Result.failure(AuditError.of(ERROR_CODE_AUDIT_LOG_FAILED,
                    "Failed to log encryption event", e));
        }
    }

    @Override
    public Result<Void, AuditError> logDecryption(DecryptionEvent event) {
        Objects.requireNonNull(event, "DecryptionEvent cannot be null");
        try {
            // Decryption operations are MEDIUM level
            LogLevel level = LogLevel.MEDIUM;
            if (!shouldLog(level)) {
                return voidSuccess();
            }
            String entry = buildDecryptionEntry(event, level);
            if (event.isSuccess()) {
                log.info(entry);
            } else {
                log.warn(entry);
            }
            persistToStore("DECRYPTION", event.getTimestamp(), entry);
            return voidSuccess();
        } catch (Exception e) {
            return Result.failure(AuditError.of(ERROR_CODE_AUDIT_LOG_FAILED,
                    "Failed to log decryption event", e));
        }
    }

    @Override
    public Result<Void, AuditError> logKeyRotation(KeyRotationEvent event) {
        Objects.requireNonNull(event, "KeyRotationEvent cannot be null");
        try {
            // Key rotation is always CRITICAL – logged regardless of configuration
            LogLevel level = LogLevel.CRITICAL;
            String entry = buildKeyRotationEntry(event, level);
            log.warn(entry);
            persistToStore("KEY_ROTATION", event.getTimestamp(), entry);
            return voidSuccess();
        } catch (Exception e) {
            return Result.failure(AuditError.of(ERROR_CODE_AUDIT_LOG_FAILED,
                    "Failed to log key rotation event", e));
        }
    }

    @Override
    public Result<Void, AuditError> logSecurityEvent(SecurityEvent event) {
        Objects.requireNonNull(event, "SecurityEvent cannot be null");
        try {
            // Determine level from event severity; authentication failures are HIGH
            LogLevel level = resolveSecurityEventLevel(event);
            if (!shouldLog(level)) {
                return voidSuccess();
            }
            String entry = buildSecurityEntry(event, level);
            if (level == LogLevel.CRITICAL) {
                log.error(entry);
            } else if (level == LogLevel.HIGH) {
                log.warn(entry);
            } else {
                log.info(entry);
            }
            persistToStore("SECURITY_EVENT", event.getTimestamp(), entry);
            return voidSuccess();
        } catch (Exception e) {
            return Result.failure(AuditError.of(ERROR_CODE_AUDIT_LOG_FAILED,
                    "Failed to log security event", e));
        }
    }

    @Override
    public Result<Void, AuditError> logKeyAccess(KeyAccessEvent event) {
        Objects.requireNonNull(event, "KeyAccessEvent cannot be null");
        try {
            // Key access events are LOW level (high-volume, subject to sampling)
            LogLevel level = LogLevel.LOW;
            if (!shouldLog(level)) {
                return voidSuccess();
            }
            String entry = buildKeyAccessEntry(event, level);
            log.debug(entry);
            persistToStore("KEY_ACCESS", event.getTimestamp(), entry);
            return voidSuccess();
        } catch (Exception e) {
            return Result.failure(AuditError.of(ERROR_CODE_AUDIT_LOG_FAILED,
                    "Failed to log key access event", e));
        }
    }

    @Override
    public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) {
        Objects.requireNonNull(event, "AuditLogAccessEvent cannot be null");
        try {
            // Audit log access is HIGH level (sensitive operation)
            LogLevel level = LogLevel.HIGH;
            if (!shouldLog(level)) {
                return voidSuccess();
            }
            String entry = buildAuditLogAccessEntry(event, level);
            if (event.isSuccess()) {
                log.info(entry);
            } else {
                log.warn(entry);
            }
            persistToStore("AUDIT_LOG_ACCESS", event.getTimestamp(), entry);
            return voidSuccess();
        } catch (Exception e) {
            return Result.failure(AuditError.of(ERROR_CODE_AUDIT_LOG_FAILED,
                    "Failed to log audit log access event", e));
        }
    }

    /**
     * Resolves the {@link LogLevel} for a security event.
     *
     * <p>Authentication failures are always HIGH 
     * Events with CRITICAL severity in the event itself are CRITICAL.
     * All other security events default to HIGH.
     */
    private static LogLevel resolveSecurityEventLevel(SecurityEvent event) {
        String severity = event.getSeverity();
        if ("CRITICAL".equalsIgnoreCase(severity)) {
            return LogLevel.CRITICAL;
        }
        // Authentication failures are HIGH regardless of severity field
        String eventType = event.getEventType();
        if (eventType != null && (
                eventType.contains("AUTH") ||
                eventType.contains("AUTHENTICATION") ||
                eventType.contains("UNAUTHORIZED"))) {
            return LogLevel.HIGH;
        }
        if ("HIGH".equalsIgnoreCase(severity)) {
            return LogLevel.HIGH;
        }
        if ("MEDIUM".equalsIgnoreCase(severity)) {
            return LogLevel.MEDIUM;
        }
        if ("LOW".equalsIgnoreCase(severity)) {
            return LogLevel.LOW;
        }
        return LogLevel.HIGH; // default for security events
    }

    /**
     * Persists the signed log entry to the encrypted append-only store, if one
     * is configured. Failures are logged but do not propagate – the SLF4J log
     * is the primary audit trail; the store is a secondary durable record.
     */
    private void persistToStore(String eventType, java.time.Instant timestamp, String signedEntry) {
        if (auditLogStore == null) {
            return;
        }
        // Extract the signature that was already embedded in the entry JSON
        String signature = extractSignature(signedEntry);
        boolean persisted = auditLogStore.append(eventType, timestamp, signedEntry, signature);
        if (!persisted) {
            log.error("AuditLogger: failed to persist entry to encrypted audit log store " +
                      "for event type '{}'", eventType);
        }
    }

    /**
     * Extracts the HMAC signature value from a finished log entry JSON string.
     * The signature is always the last field before the closing brace.
     */
    private static String extractSignature(String entry) {
        // Entry format ends with: ..."signature":"<hex>"}
        int sigIdx = entry.lastIndexOf("\"signature\":\"");
        if (sigIdx < 0) {
            return "SIGNATURE_UNAVAILABLE";
        }
        int valueStart = sigIdx + "\"signature\":\"".length();
        int valueEnd = entry.indexOf("\"", valueStart);
        if (valueEnd < 0) {
            return "SIGNATURE_UNAVAILABLE";
        }
        return entry.substring(valueStart, valueEnd);
    }

    /**
     * Returns a successful {@code Result<Void, AuditError>}.
     *
     * <p>{@code Void} cannot be instantiated, so we use an unchecked raw cast
     * which is safe at runtime because generic types are erased.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Result<Void, AuditError> voidSuccess() {
        return (Result<Void, AuditError>) (Result) Result.success(Unit.unit());
    }

    // -------------------------------------------------------------------------
    // Entry builders – produce structured log strings
    // -------------------------------------------------------------------------

    private String buildEncryptionEntry(EncryptionEvent event, LogLevel level) {
        StringBuilder sb = startEntry("ENCRYPTION", event.getTimestamp(),
                event.getContext(), event.getServiceIdentity(), level);
        appendOptional(sb, "userContext", event.getUserContext());
        appendOptional(sb, "keyId", event.getKeyId());
        appendOptional(sb, "fieldIdentifier", event.getFieldIdentifier());
        appendBoolean(sb, "success", event.isSuccess());
        appendOptional(sb, "errorCode", event.getErrorCode());
        appendMetadata(sb, event.getMetadata());
        return finishEntry(sb);
    }

    private String buildDecryptionEntry(DecryptionEvent event, LogLevel level) {
        StringBuilder sb = startEntry("DECRYPTION", event.getTimestamp(),
                event.getContext(), event.getServiceIdentity(), level);
        appendOptional(sb, "userContext", event.getUserContext());
        appendOptional(sb, "keyId", event.getKeyId());
        appendOptional(sb, "fieldIdentifier", event.getFieldIdentifier());
        appendBoolean(sb, "success", event.isSuccess());
        appendOptional(sb, "errorCode", event.getErrorCode());
        appendMetadata(sb, event.getMetadata());
        return finishEntry(sb);
    }

    private String buildKeyRotationEntry(KeyRotationEvent event, LogLevel level) {
        StringBuilder sb = startEntry("KEY_ROTATION", event.getTimestamp(),
                event.getContext(), event.getServiceIdentity(), level);
        appendOptional(sb, "oldKeyId", event.getOldKeyId());
        appendOptional(sb, "newKeyId", event.getNewKeyId());
        appendOptional(sb, "keyType", event.getKeyType());
        appendOptional(sb, "rotationReason", event.getRotationReason());
        appendBoolean(sb, "success", event.isSuccess());
        appendOptional(sb, "errorCode", event.getErrorCode());
        appendMetadata(sb, event.getMetadata());
        return finishEntry(sb);
    }

    private String buildSecurityEntry(SecurityEvent event, LogLevel level) {
        StringBuilder sb = startEntry("SECURITY_EVENT", event.getTimestamp(),
                event.getContext(), event.getServiceIdentity(), level);
        appendOptional(sb, "userContext", event.getUserContext());
        appendField(sb, "securityEventType", event.getEventType());
        appendField(sb, "severity", event.getSeverity());
        appendOptional(sb, "keyId", event.getKeyId());
        appendOptional(sb, "fieldIdentifier", event.getFieldIdentifier());
        appendOptional(sb, "description", event.getDescription());
        appendMetadata(sb, event.getMetadata());
        return finishEntry(sb);
    }

    private String buildKeyAccessEntry(KeyAccessEvent event, LogLevel level) {
        StringBuilder sb = startEntry("KEY_ACCESS", event.getTimestamp(),
                event.getContext(), event.getServiceIdentity(), level);
        appendOptional(sb, "keyId", event.getKeyId());
        appendOptional(sb, "keyType", event.getKeyType());
        appendOptional(sb, "accessType", event.getAccessType());
        appendBoolean(sb, "success", event.isSuccess());
        appendOptional(sb, "errorCode", event.getErrorCode());
        appendMetadata(sb, event.getMetadata());
        return finishEntry(sb);
    }

    private String buildAuditLogAccessEntry(AuditLogAccessEvent event, LogLevel level) {
        StringBuilder sb = startEntry("AUDIT_LOG_ACCESS", event.getTimestamp(),
                event.getContext(), event.getServiceIdentity(), level);
        appendField(sb, "accessorIdentity", event.getAccessorIdentity());
        appendOptional(sb, "accessDescription", event.getAccessDescription());
        appendBoolean(sb, "success", event.isSuccess());
        appendOptional(sb, "errorCode", event.getErrorCode());
        appendMetadata(sb, event.getMetadata());
        return finishEntry(sb);
    }

    // -------------------------------------------------------------------------
    // Structured entry helpers
    // -------------------------------------------------------------------------

    /**
     * Opens a new log entry with the mandatory fields that every entry must carry.
     * Includes the log level for filtering and audit trail purposes.
     */
    private StringBuilder startEntry(String eventType, Instant timestamp,
                                     BoundedContext context, String svcIdentity,
                                     LogLevel level) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("{");
        appendField(sb, "eventType", eventType);
        appendField(sb, "timestamp", timestamp.toString());
        appendField(sb, "context", context.name());
        appendField(sb, "serviceIdentity", svcIdentity);
        appendField(sb, "level", level.name());
        return sb;
    }

    /**
     * Appends the HMAC signature and closes the JSON object.
     */
    private String finishEntry(StringBuilder sb) {
        // Build the payload to sign (everything so far, without the closing brace)
        String payload = sb.toString();
        String signature = computeSignature(payload);
        appendField(sb, "signature", signature);
        sb.append("}");
        return sb.toString();
    }

    private void appendField(StringBuilder sb, String key, String value) {
        sb.append("\"").append(key).append("\":\"").append(escape(value)).append("\",");
    }

    private void appendBoolean(StringBuilder sb, String key, boolean value) {
        sb.append("\"").append(key).append("\":").append(value).append(",");
    }

    private void appendOptional(StringBuilder sb, String key, String value) {
        if (value != null && !value.isEmpty()) {
            appendField(sb, key, value);
        }
    }

    private void appendOptional(StringBuilder sb, String key, UUID value) {
        if (value != null) {
            appendField(sb, key, value.toString());
        }
    }

    private void appendMetadata(StringBuilder sb, Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return;
        }
        sb.append("\"metadata\":{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            Object val = entry.getValue();
            if (val instanceof Number) {
                sb.append("\"").append(escape(entry.getKey())).append("\":").append(val);
            } else if (val instanceof Boolean) {
                sb.append("\"").append(escape(entry.getKey())).append("\":").append(val);
            } else {
                sb.append("\"").append(escape(entry.getKey())).append("\":\"")
                  .append(escape(String.valueOf(val))).append("\"");
            }
        }
        sb.append("},");
    }

    // -------------------------------------------------------------------------
    // HMAC-SHA256 signing
    // -------------------------------------------------------------------------

    /**
     * Computes an HMAC-SHA256 signature over the given payload using the
     * configured signing key. Returns a hex-encoded string.
     */
    private String computeSignature(String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(signingKey, HMAC_ALGORITHM));
            byte[] hmac = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hmac);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            // Fallback: log without signature rather than swallowing the event
            log.error("AuditLogger: failed to compute HMAC signature", e);
            return "SIGNATURE_UNAVAILABLE";
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /** Minimal JSON string escaping to prevent log injection. */
    private static String escape(String value) {
        if (value == null) return "";
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}