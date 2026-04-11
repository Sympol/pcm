package dev.vibeafrika.pcm.infrastructure.spring.encryption.network;

import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.IAuditLogger;
import dev.vibeafrika.pcm.domain.encryption.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Intercepts KMS connection attempts to enforce IP allowlist and log all attempts.
 *
 * <p>Responsibilities :
 * <ul>
 *   <li>Log every KMS connection attempt with source IP, destination, and timestamp</li>
 *   <li>Validate source IP against the configured allowlist</li>
 *   <li>Deny connections from unauthorized IPs and log a security event</li>
 *   <li>Integrate with {@link IAuditLogger} for structured audit trail</li>
 * </ul>
 *
 * <p>This interceptor is designed to be called by KMS client wrappers before
 * each outbound KMS request. It does not perform actual HTTP interception —
 * instead it provides a {@link #checkConnection(String, String)} method that
 * KMS clients invoke to validate and log each connection attempt.
 */
public class KmsConnectionInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(KmsConnectionInterceptor.class);

    private static final String SERVICE_IDENTITY = "KmsConnectionInterceptor";

    private final List<String> allowedServiceIps;
    private final boolean privateSubnetOnly;

    /** Optional audit logger; may be null when running without full Spring context. */
    private IAuditLogger auditLogger;

    /**
     * Creates an interceptor with an IP allowlist and private-subnet enforcement.
     *
     * @param allowedServiceIps list of authorized source IP addresses; empty means
     *                          no IP restriction (not recommended for production)
     * @param privateSubnetOnly when {@code true}, connections from public IPs are
     *                          rejected even if they appear in the allowlist
     */
    public KmsConnectionInterceptor(List<String> allowedServiceIps, boolean privateSubnetOnly) {
        this.allowedServiceIps = allowedServiceIps != null
                ? Collections.unmodifiableList(allowedServiceIps)
                : Collections.emptyList();
        this.privateSubnetOnly = privateSubnetOnly;
    }

    /**
     * Sets the audit logger used to record security events.
     *
     * <p>Optional — when not set, security events are only written to SLF4J.
     *
     * @param auditLogger the audit logger to use
     */
    public void setAuditLogger(IAuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }

    /**
     * Validates and logs a KMS connection attempt.
     *
     * <p>Returns {@code true} if the connection is permitted, {@code false} if it
     * should be rejected. Callers MUST honour the return value and abort the
     * connection when {@code false} is returned.
     *
     * @param sourceIp        the IP address of the service initiating the KMS call
     * @param kmsDestination  the KMS endpoint URL or hostname being contacted
     * @return {@code true} if the connection is authorized, {@code false} otherwise
     */
    public boolean checkConnection(String sourceIp, String kmsDestination) {
        Objects.requireNonNull(sourceIp, "sourceIp cannot be null");
        Objects.requireNonNull(kmsDestination, "kmsDestination cannot be null");

        Instant timestamp = Instant.now();

        // 1. Log the connection attempt 
        logger.info("KMS connection attempt: sourceIp={}, destination={}, timestamp={}",
                    sourceIp, kmsDestination, timestamp);

        // 2. Validate private subnet 
        if (privateSubnetOnly && !NetworkSecurityConfiguration.isPrivateSubnetAddress(sourceIp)) {
            logUnauthorizedAccess(sourceIp, kmsDestination, timestamp,
                    "Source IP is not in a private subnet");
            return false;
        }

        // 3. Validate IP allowlist 
        if (!allowedServiceIps.isEmpty() && !allowedServiceIps.contains(sourceIp)) {
            logUnauthorizedAccess(sourceIp, kmsDestination, timestamp,
                    "Source IP is not in the authorized service IP allowlist");
            return false;
        }

        logger.debug("KMS connection authorized: sourceIp={}, destination={}", sourceIp, kmsDestination);
        return true;
    }

    /**
     * Logs an unauthorized KMS connection attempt as a HIGH-severity security event.
     *
     * @param sourceIp       the unauthorized source IP
     * @param destination    the KMS endpoint that was targeted
     * @param timestamp      when the attempt occurred
     * @param reason         human-readable reason for rejection
     */
    private void logUnauthorizedAccess(String sourceIp, String destination,
                                       Instant timestamp, String reason) {
        logger.warn("KMS connection DENIED: sourceIp={}, destination={}, reason={}",
                    sourceIp, destination, reason);

        if (auditLogger != null) {
            SecurityEvent event = SecurityEvent.builder()
                    .timestamp(timestamp)
                    .context(BoundedContext.PROFILE) // generic context for network-level events
                    .serviceIdentity(SERVICE_IDENTITY)
                    .eventType("UNAUTHORIZED_KMS_CONNECTION")
                    .severity("HIGH")
                    .description("Unauthorized KMS connection attempt from " + sourceIp +
                                 " to " + destination + ": " + reason)
                    .metadata(Map.of(
                            "sourceIp", sourceIp,
                            "destination", destination,
                            "reason", reason
                    ))
                    .build();

            auditLogger.logSecurityEvent(event);
        }
    }

    /**
     * Returns the configured IP allowlist (unmodifiable).
     */
    public List<String> getAllowedServiceIps() {
        return allowedServiceIps;
    }

    /**
     * Returns whether private-subnet-only mode is active.
     */
    public boolean isPrivateSubnetOnly() {
        return privateSubnetOnly;
    }
}
