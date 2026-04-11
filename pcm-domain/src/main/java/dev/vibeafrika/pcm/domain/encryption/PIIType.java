package dev.vibeafrika.pcm.domain.encryption;

/**
 * Classification of PII field types for encryption policy.
 *
 * <p>Per GDPR :
 * <ul>
 *   <li>{@link #STANDARD_PII} – email, phone number</li>
 *   <li>{@link #SENSITIVE_PII} – health data, biometric data</li>
 *   <li>{@link #QUASI_IDENTIFIER} – IP address, user agent (can identify when combined)</li>
 * </ul>
 *
 * <p>All three categories require AES-256-GCM encryption.
 */
public enum PIIType {

    /**
     * Common PII such as email addresses and phone numbers.
     * Requires AES-256-GCM encryption.
     */
    STANDARD_PII,

    /**
     * Highly sensitive PII such as health data and biometric data.
     * Requires AES-256-GCM encryption with the highest protection level.
     */
    SENSITIVE_PII,

    /**
     * Data that can identify individuals when combined with other data,
     * such as IP addresses and user agents.
     * Requires AES-256-GCM encryption.
     */
    QUASI_IDENTIFIER
}
