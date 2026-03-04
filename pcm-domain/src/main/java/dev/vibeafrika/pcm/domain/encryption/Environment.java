package dev.vibeafrika.pcm.domain.encryption;

/**
 * Represents the deployment environment for key isolation.
 * Each environment has separate root KEKs to prevent cross-environment key reuse.
 */
public enum Environment {
    DEV,
    STAGING,
    PROD
}
