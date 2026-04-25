package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.infrastructure.encryption.entity.AuditLogEntryEntity;
import dev.vibeafrika.pcm.infrastructure.encryption.repository.AuditLogEntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Append-only, encrypted audit log store.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Encrypt each log entry payload with AES-256-GCM using a dedicated
 *       audit log encryption key (separate from DEK/KEK used for PII).</li>
 *   <li>Persist entries via {@link AuditLogEntryRepository}, which enforces
 *       append-only semantics by prohibiting delete operations.</li>
 *   <li>Store the HMAC-SHA256 signature alongside the encrypted payload so
 *       that integrity can be verified without decryption.</li>
 * </ul>
 *
 * <p>The audit log encryption key is completely separate from the DEK/KEK
 * hierarchy used for PII encryption. It is provided at construction time and
 * must be 32 bytes (256 bits) for AES-256.
 *
 * <p>Each entry is encrypted with a fresh random 96-bit IV (12 bytes) generated
 * by {@link SecureRandom}. The IV is prepended to the ciphertext in the stored
 * byte array: {@code [IV (12 bytes) | GCM ciphertext + tag]}.
 */
public class AuditLogStore {

    private static final Logger log = LoggerFactory.getLogger(AuditLogStore.class);

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int AES_KEY_LENGTH = 32; // 256 bits

    private final AuditLogEntryRepository repository;
    private final SecretKeySpec auditLogKey;
    private final SecureRandom secureRandom;

    /** Monotonically increasing sequence counter for gap detection. */
    private final AtomicLong sequenceCounter = new AtomicLong(0);

    /**
     * Creates an {@code AuditLogStore}.
     *
     * @param repository     append-only JPA repository for persisting entries
     * @param auditLogKeyBytes 32-byte AES-256 key used exclusively for audit log
     *                        encryption (must NOT be the same key used for PII)
     * @throws IllegalArgumentException if {@code auditLogKeyBytes} is not 32 bytes
     */
    public AuditLogStore(AuditLogEntryRepository repository, byte[] auditLogKeyBytes) {
        this.repository = repository;
        if (auditLogKeyBytes == null || auditLogKeyBytes.length != AES_KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "Audit log encryption key must be exactly 32 bytes (256 bits)");
        }
        // Defensive copy – never hold a reference to the caller's array
        byte[] keyCopy = auditLogKeyBytes.clone();
        this.auditLogKey = new SecretKeySpec(keyCopy, "AES");
        Arrays.fill(keyCopy, (byte) 0); // wipe the local copy
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypts {@code plaintext} with AES-256-GCM and persists the result as an
     * immutable audit log entry.
     *
     * @param eventType  short label for the event (e.g. "ENCRYPTION")
     * @param timestamp  wall-clock time of the original event
     * @param plaintext  the structured log entry JSON string
     * @param hmacSignature hex-encoded HMAC-SHA256 signature already computed
     *                      over {@code plaintext} by the caller
     * @return {@code true} if the entry was persisted successfully
     */
    @Transactional
    public boolean append(String eventType, Instant timestamp,
                          String plaintext, String hmacSignature) {
        try {
            byte[] encryptedPayload = encrypt(plaintext);
            long seq = sequenceCounter.incrementAndGet();
            AuditLogEntryEntity entity = new AuditLogEntryEntity(
                    seq, eventType, timestamp, encryptedPayload, hmacSignature);
            repository.save(entity);
            return true;
        } catch (Exception e) {
            log.error("AuditLogStore: failed to persist encrypted audit log entry " +
                      "for event type '{}': {}", eventType, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Verifies the integrity of a stored entry by re-computing the HMAC over
     * the decrypted payload and comparing it to the stored signature.
     *
     * @param entity    the stored entity to verify
     * @param hmacVerifier function that computes HMAC over a plaintext string
     * @return {@code true} if the signature matches the decrypted payload
     */
    public boolean verifyIntegrity(AuditLogEntryEntity entity,
                                   java.util.function.Function<String, String> hmacVerifier) {
        try {
            String decrypted = decrypt(entity.getEncryptedPayload());
            String expectedSignature = hmacVerifier.apply(decrypted);
            return constantTimeEquals(expectedSignature, entity.getHmacSignature());
        } catch (Exception e) {
            log.warn("AuditLogStore: integrity verification failed for entry id={}: {}",
                     entity.getId(), e.getMessage());
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Encryption / Decryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with AES-256-GCM.
     * Output format: {@code [IV (12 bytes) | GCM ciphertext+tag]}.
     */
    byte[] encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, auditLogKey,
                new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        byte[] ciphertextWithTag = cipher.doFinal(
                plaintext.getBytes(StandardCharsets.UTF_8));

        // Prepend IV so it can be extracted during decryption
        byte[] result = new byte[GCM_IV_LENGTH + ciphertextWithTag.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(ciphertextWithTag, 0, result, GCM_IV_LENGTH, ciphertextWithTag.length);
        return result;
    }

    /**
     * Decrypts a payload previously produced by {@link #encrypt(String)}.
     */
    String decrypt(byte[] encryptedPayload) throws Exception {
        if (encryptedPayload == null || encryptedPayload.length <= GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted payload: too short");
        }
        byte[] iv = Arrays.copyOfRange(encryptedPayload, 0, GCM_IV_LENGTH);
        byte[] ciphertextWithTag = Arrays.copyOfRange(
                encryptedPayload, GCM_IV_LENGTH, encryptedPayload.length);

        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.DECRYPT_MODE, auditLogKey,
                new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        byte[] plainBytes = cipher.doFinal(ciphertextWithTag);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /** Constant-time string comparison to prevent timing attacks. */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        if (aBytes.length != bBytes.length) return false;
        int diff = 0;
        for (int i = 0; i < aBytes.length; i++) {
            diff |= aBytes[i] ^ bBytes[i];
        }
        return diff == 0;
    }
}
