package dev.vibeafrika.pcm.domain.encryption;

/**
 * Represents the bounded contexts in PCM where PII encryption is applied.
 * Each context has isolated KEKs for security.
 */
public enum BoundedContext {
    PROFILE,
    CONSENT,
    SEGMENT,
    PREFERENCE
}
