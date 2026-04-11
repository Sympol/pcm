package dev.vibeafrika.pcm.domain.encryption;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a JPA entity field as containing PII that must be encrypted at rest.
 *
 * <p>Place this annotation on {@code String} fields in JPA entities that hold
 * personally identifiable information. The infrastructure encryption listener
 * will transparently encrypt the field before persistence and decrypt it after
 * loading, keeping the domain layer unaware of encryption details.
 *
 * <p>Example usage:
 * <pre>{@code
 * @EncryptedField(piiType = PIIType.STANDARD_PII, searchable = true,
 *                blindIndexField = "emailBlindIndex")
 * @Column(name = "email")
 * private String email;
 *
 * @Column(name = "email_blind_index")
 * private String emailBlindIndex;
 * }</pre>
 *
 * <p>For searchable fields, a companion column named {@code blindIndexField} must
 * exist on the entity to store the HMAC-SHA256 blind index.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface EncryptedField {

    /**
     * The PII classification of this field.
     * All types receive AES-256-GCM encryption.
     */
    PIIType piiType();

    /**
     * Whether this field supports exact-match searching via a blind index.
     * When {@code true}, a {@link #blindIndexField()} must be specified.
     */
    boolean searchable() default false;

    /**
     * The name of the companion entity field that stores the blind index.
     * Required when {@link #searchable()} is {@code true}.
     * The companion column must be a {@code String} field on the same entity.
     */
    String blindIndexField() default "";
}
