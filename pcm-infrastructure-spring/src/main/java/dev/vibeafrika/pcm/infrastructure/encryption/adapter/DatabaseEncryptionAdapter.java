package dev.vibeafrika.pcm.infrastructure.encryption.adapter;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.BlindIndexService;

import java.lang.reflect.Field;
import java.util.*;

/**
 * Adapter that provides transparent field-level encryption for JPA entities.
 *
 * <p>Responsibilities :
 * <ul>
 *   <li>Discover {@link EncryptedField}-annotated fields via reflection</li>
 *   <li>Encrypt PII fields before database write</li>
 *   <li>Decrypt PII fields after database read</li>
 *   <li>Generate HMAC-SHA256 blind indexes for searchable fields</li>
 *   <li>Store blind indexes in companion columns</li>
 * </ul>
 *
 * <p>The adapter is framework-agnostic; it is invoked by the Spring-specific
 * {@link EncryptionEntityListener} which hooks into JPA lifecycle callbacks.
 *
 * <p>Ciphertext is stored as a Base64-encoded string so it fits in standard
 * {@code VARCHAR} / {@code TEXT} columns without schema changes.
 */
public class DatabaseEncryptionAdapter {

    private final IEncryptionService encryptionService;
    private final BlindIndexService blindIndexService;
    private final BoundedContext defaultContext;

    /**
     * Cache of field metadata per entity class to avoid repeated reflection.
     * Key: entity class, Value: list of annotated field descriptors.
     */
    private final Map<Class<?>, List<EncryptedFieldDescriptor>> fieldCache =
            new java.util.concurrent.ConcurrentHashMap<>();

    public DatabaseEncryptionAdapter(
            IEncryptionService encryptionService,
            BlindIndexService blindIndexService,
            BoundedContext defaultContext) {
        this.encryptionService = Objects.requireNonNull(encryptionService, "EncryptionService cannot be null");
        this.blindIndexService = Objects.requireNonNull(blindIndexService, "BlindIndexService cannot be null");
        this.defaultContext = Objects.requireNonNull(defaultContext, "Default BoundedContext cannot be null");
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Encrypts all {@link EncryptedField}-annotated fields on the entity and
     * generates blind indexes for searchable fields.
     *
     * <p>Called by {@link EncryptionEntityListener#prePersist(Object)} before
     * INSERT / UPDATE operations.
     *
     * @param entity the JPA entity whose PII fields should be encrypted
     * @throws EncryptionAdapterException if encryption fails for any field
     */
    public void encryptEntity(Object entity) {
        Objects.requireNonNull(entity, "Entity cannot be null");
        List<EncryptedFieldDescriptor> descriptors = getDescriptors(entity.getClass());

        for (EncryptedFieldDescriptor descriptor : descriptors) {
            // Validate searchable field configuration eagerly before any encryption
            if (descriptor.annotation().searchable()) {
                String blindIndexFieldName = descriptor.annotation().blindIndexField();
                if (blindIndexFieldName == null || blindIndexFieldName.isBlank()) {
                    throw new EncryptionAdapterException(
                            "Field '" + descriptor.field().getName() +
                            "' is marked searchable but blindIndexField is not specified");
                }
                Field blindField = findField(entity.getClass(), blindIndexFieldName);
                if (blindField == null) {
                    throw new EncryptionAdapterException(
                            "Blind index field '" + blindIndexFieldName +
                            "' not found on entity " + entity.getClass().getSimpleName());
                }
            }

            String plaintext = readStringField(entity, descriptor.field());
            if (plaintext == null) {
                continue; // null fields are left as-is
            }

            // Encrypt the field value
            Result<Ciphertext, EncryptionError> encResult =
                    encryptionService.encrypt(plaintext, defaultContext);
            if (encResult.isFailure()) {
                EncryptionError err = encResult.getError().orElseThrow();
                throw new EncryptionAdapterException(
                        "Failed to encrypt field '" + descriptor.field().getName() + "': " + err.getMessage());
            }

            byte[] ciphertextBytes = encResult.getValue().orElseThrow().getValue();
            String encoded = Base64.getEncoder().encodeToString(ciphertextBytes);
            writeStringField(entity, descriptor.field(), encoded);

            // Generate blind index for searchable fields
            if (descriptor.annotation().searchable()) {
                generateAndStoreBlindIndex(entity, descriptor, plaintext);
            }
        }
    }

    /**
     * Decrypts all {@link EncryptedField}-annotated fields on the entity.
     *
     * <p>Called by {@link EncryptionEntityListener#postLoad(Object)} after
     * SELECT operations.
     *
     * @param entity the JPA entity whose PII fields should be decrypted
     * @throws EncryptionAdapterException if decryption fails for any field
     */
    public void decryptEntity(Object entity) {
        Objects.requireNonNull(entity, "Entity cannot be null");
        List<EncryptedFieldDescriptor> descriptors = getDescriptors(entity.getClass());

        for (EncryptedFieldDescriptor descriptor : descriptors) {
            String encoded = readStringField(entity, descriptor.field());
            if (encoded == null) {
                continue; // null fields are left as-is
            }

            byte[] ciphertextBytes;
            try {
                ciphertextBytes = Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                // Field may already be plaintext (e.g., during migration) – skip silently
                continue;
            }

            Ciphertext ciphertext;
            try {
                ciphertext = Ciphertext.of(ciphertextBytes);
            } catch (IllegalArgumentException e) {
                // Too short to be a valid ciphertext – skip
                continue;
            }

            Result<String, DecryptionError> decResult =
                    encryptionService.decrypt(ciphertext, defaultContext);
            if (decResult.isFailure()) {
                DecryptionError err = decResult.getError().orElseThrow();
                throw new EncryptionAdapterException(
                        "Failed to decrypt field '" + descriptor.field().getName() + "': " + err.getMessage());
            }

            writeStringField(entity, descriptor.field(), decResult.getValue().orElseThrow());
        }
    }

    /**
     * Encrypts a batch of entities efficiently.
     *
     * <p>Delegates to {@link #encryptEntity(Object)} for each entity.
     * The underlying {@link IEncryptionService} reuses the same DEK across
     * the batch, minimising KMS round-trips.
     *
     * @param entities the entities to encrypt
     */
    public void encryptBatch(List<?> entities) {
        Objects.requireNonNull(entities, "Entities list cannot be null");
        for (Object entity : entities) {
            encryptEntity(entity);
        }
    }

    /**
     * Decrypts a batch of entities efficiently.
     *
     * @param entities the entities to decrypt
     */
    public void decryptBatch(List<?> entities) {
        Objects.requireNonNull(entities, "Entities list cannot be null");
        for (Object entity : entities) {
            decryptEntity(entity);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void generateAndStoreBlindIndex(
            Object entity,
            EncryptedFieldDescriptor descriptor,
            String plaintext) {

        String blindIndexFieldName = descriptor.annotation().blindIndexField();

        // Use the entity's identity hash as a stable per-record salt
        String recordSalt = Integer.toHexString(System.identityHashCode(entity));

        Result<BlindIndex, EncryptionError> biResult =
                blindIndexService.generateBlindIndex(plaintext, recordSalt);
        if (biResult.isFailure()) {
            EncryptionError err = biResult.getError().orElseThrow();
            throw new EncryptionAdapterException(
                    "Failed to generate blind index for field '" +
                    descriptor.field().getName() + "': " + err.getMessage());
        }

        String blindIndexValue = biResult.getValue().orElseThrow().getValue();

        // Write blind index to companion field
        Field blindField = findField(entity.getClass(), blindIndexFieldName);
        writeStringField(entity, blindField, blindIndexValue);
    }

    private List<EncryptedFieldDescriptor> getDescriptors(Class<?> entityClass) {
        return fieldCache.computeIfAbsent(entityClass, this::discoverFields);
    }

    private List<EncryptedFieldDescriptor> discoverFields(Class<?> entityClass) {
        List<EncryptedFieldDescriptor> result = new ArrayList<>();
        Class<?> current = entityClass;
        while (current != null && current != Object.class) {
            for (Field field : current.getDeclaredFields()) {
                EncryptedField annotation = field.getAnnotation(EncryptedField.class);
                if (annotation != null) {
                    if (!field.getType().equals(String.class)) {
                        throw new EncryptionAdapterException(
                                "@EncryptedField can only be applied to String fields, but field '" +
                                field.getName() + "' on " + entityClass.getSimpleName() +
                                " is of type " + field.getType().getSimpleName());
                    }
                    field.setAccessible(true);
                    result.add(new EncryptedFieldDescriptor(field, annotation));
                }
            }
            current = current.getSuperclass();
        }
        return Collections.unmodifiableList(result);
    }

    private static String readStringField(Object entity, Field field) {
        try {
            return (String) field.get(entity);
        } catch (IllegalAccessException e) {
            throw new EncryptionAdapterException(
                    "Cannot read field '" + field.getName() + "': " + e.getMessage(), e);
        }
    }

    private static void writeStringField(Object entity, Field field, String value) {
        try {
            field.setAccessible(true);
            field.set(entity, value);
        } catch (IllegalAccessException e) {
            throw new EncryptionAdapterException(
                    "Cannot write field '" + field.getName() + "': " + e.getMessage(), e);
        }
    }

    private static Field findField(Class<?> clazz, String fieldName) {
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            try {
                Field f = current.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Inner types
    // -------------------------------------------------------------------------

    /** Immutable descriptor pairing a reflected field with its annotation. */
    private record EncryptedFieldDescriptor(Field field, EncryptedField annotation) {}
}
