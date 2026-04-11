package dev.vibeafrika.pcm.domain.encryption;

/**
 * Distinguishes between system-initiated and human-initiated access in audit log entries.
 *
 * <p>THE Audit_Logger SHALL distinguish between system access
 * and human access in log entries.
 */
public enum AccessType {

    /** Access performed by an automated system or service account. */
    SYSTEM,

    /** Access performed by a human operator or administrator. */
    HUMAN
}
