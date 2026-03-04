package dev.vibeafrika.pcm.domain.encryption;

/**
 * Represents the lifecycle status of an encryption key.
 */
public enum KeyStatus {
    ACTIVE,
    ROTATED,
    COMPROMISED,
    DELETED
}
