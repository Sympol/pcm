package dev.vibeafrika.pcm.segment.infrastructure.persistence.listener;

import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

import java.util.function.Consumer;

/**
 * JPA entity listener that applies transparent PII encryption to Segment entities.
 *
 * <p>Uses a static delegate pattern so that the Spring-managed
 * {@code DatabaseEncryptionAdapter} can be injected at startup without
 * creating a circular module dependency between {@code segment-infrastructure}
 * and {@code pcm-infrastructure-spring}.
 *
 * <p>The encrypt/decrypt consumers are set by
 * {@code DatabaseEncryptionAdapterConfiguration} during application startup.
 *
 * <p>Note: {@link dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity}
 * currently has no direct PII String fields (tags and scores are behavioral/analytical data).
 * This listener is in place to establish the bounded context encryption pattern for the
 * Segment context and to support future PII fields.
 */
public class SegmentEncryptionEntityListener {

    private static Consumer<Object> encryptDelegate;
    private static Consumer<Object> decryptDelegate;

    /**
     * Sets the encryption delegates. Called by Spring infrastructure at startup.
     *
     * @param encrypt consumer that encrypts PII fields on an entity
     * @param decrypt consumer that decrypts PII fields on an entity
     */
    public static void setDelegates(Consumer<Object> encrypt, Consumer<Object> decrypt) {
        encryptDelegate = encrypt;
        decryptDelegate = decrypt;
    }

    @PrePersist
    public void prePersist(Object entity) {
        if (encryptDelegate != null) {
            encryptDelegate.accept(entity);
        }
    }

    @PreUpdate
    public void preUpdate(Object entity) {
        if (encryptDelegate != null) {
            encryptDelegate.accept(entity);
        }
    }

    @PostLoad
    public void postLoad(Object entity) {
        if (decryptDelegate != null) {
            decryptDelegate.accept(entity);
        }
    }
}
