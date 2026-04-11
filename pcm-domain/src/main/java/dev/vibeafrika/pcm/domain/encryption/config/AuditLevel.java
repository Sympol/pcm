package dev.vibeafrika.pcm.domain.encryption.config;

/**
 * Audit logging level for the {@link AuditConfigurationModel}.
 *
 * <p>Levels are ordered from most to least severe:
 * <ol>
 *   <li>{@link #CRITICAL} – key rotation, access failures; always logged.</li>
 *   <li>{@link #HIGH} – authentication failures and important security events.</li>
 *   <li>{@link #MEDIUM} – normal encryption/decryption operations.</li>
 *   <li>{@link #LOW} – verbose/diagnostic events subject to sampling.</li>
 * </ol>
 */
public enum AuditLevel {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
}
