package dev.vibeafrika.pcm.infrastructure.encryption.adapter;

import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * JPA entity listener that provides transparent PII encryption.
 *
 * <p>Hooks into the JPA lifecycle to:
 * <ul>
 *   <li>{@link PrePersist} / {@link PreUpdate} – encrypt PII fields before INSERT/UPDATE</li>
 *   <li>{@link PostLoad} – decrypt PII fields after SELECT</li>
 * </ul>
 *
 * <p>Register this listener on a JPA entity using:
 * <pre>{@code
 * @Entity
 * @EntityListeners(EncryptionEntityListener.class)
 * public class MyEntity { ... }
 * }</pre>
 *
 * <p>Spring injects the {@link DatabaseEncryptionAdapter} via
 * {@link org.springframework.context.ApplicationContext} because JPA instantiates
 * entity listeners outside the Spring container. The static setter pattern used
 * here is the standard approach for Spring + JPA listener integration.
 */
public class EncryptionEntityListener {

    /**
     * Static reference to the adapter, set by Spring during application startup.
     * Using a static field is the conventional approach for JPA entity listeners
     * that need Spring-managed dependencies.
     */
    private static DatabaseEncryptionAdapter adapter;

    /**
     * Called by Spring to inject the adapter into all listener instances.
     * Optional — if no DatabaseEncryptionAdapter bean is present (e.g. in tests
     * where KMS is not configured), the listener silently skips encryption.
     */
    @Autowired(required = false)
    public void setAdapter(DatabaseEncryptionAdapter adapter) {
        EncryptionEntityListener.adapter = adapter;
    }

    /**
     * Encrypts PII fields before INSERT operations.
     * Rolls back the transaction if encryption fails.
     *
     * @param entity the entity about to be persisted
     */
    @PrePersist
    public void prePersist(Object entity) {
        if (adapter != null) {
            adapter.encryptEntity(entity);
        }
    }

    /**
     * Encrypts PII fields before UPDATE operations.
     * Re-encrypts with the current active DEK.
     *
     * @param entity the entity about to be updated
     */
    @PreUpdate
    public void preUpdate(Object entity) {
        if (adapter != null) {
            adapter.encryptEntity(entity);
        }
    }

    /**
     * Decrypts PII fields after SELECT operations.
     * The domain layer receives plaintext values.
     *
     * @param entity the entity just loaded from the database
     */
    @PostLoad
    public void postLoad(Object entity) {
        if (adapter != null) {
            adapter.decryptEntity(entity);
        }
    }
}
