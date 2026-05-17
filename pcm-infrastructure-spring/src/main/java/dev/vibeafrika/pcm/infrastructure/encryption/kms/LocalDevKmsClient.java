package dev.vibeafrika.pcm.infrastructure.encryption.kms;

import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.DEK;
import dev.vibeafrika.pcm.domain.encryption.EncryptedDEK;
import dev.vibeafrika.pcm.domain.encryption.Environment;
import dev.vibeafrika.pcm.domain.encryption.IKMSClient;
import dev.vibeafrika.pcm.domain.encryption.KMSError;
import dev.vibeafrika.pcm.domain.encryption.KMSHealth;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.Unit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory KMS client for unit tests and CI environments without Vault.
 *
 * <p><strong>WARNING: This implementation stores KEKs in memory and is NOT suitable
 * for any environment where data must survive a restart.</strong>
 *
 * <p>Activated only when {@code pcm.encryption.kms.provider=LOCAL} is explicitly set.
 * When running with docker-compose (which includes a Vault instance), use
 * {@code pcm.encryption.kms.provider=VAULT} instead.
 *
 * <p>Uses AES-256-GCM to wrap/unwrap DEKs with in-memory KEKs, providing
 * real encryption semantics so that the full encryption pipeline is exercised
 * in unit tests without any external dependency.
 *
 * <p>All state is lost on application restart — this is intentional for isolated tests.
 */
@Component
@ConditionalOnMissingBean(IKMSClient.class)
@ConditionalOnProperty(name = "pcm.encryption.kms.provider", havingValue = "LOCAL")
public class LocalDevKmsClient implements IKMSClient {

    private static final Logger logger = LoggerFactory.getLogger(LocalDevKmsClient.class);

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int KEK_SIZE_BYTES = 32; // AES-256

    private final SecureRandom secureRandom = new SecureRandom();

    /** In-memory KEK store: kekId → raw 256-bit key material. */
    private final Map<UUID, byte[]> kekStore = new ConcurrentHashMap<>();

    /** In-memory secret store: secretId → encrypted secret bytes. */
    private final Map<UUID, byte[]> secretStore = new ConcurrentHashMap<>();

    /** KEK used to encrypt secrets (generated once at startup). */
    private final UUID secretKekId;

    public LocalDevKmsClient() {
        // Pre-generate a KEK for secret storage
        secretKekId = UUID.randomUUID();
        byte[] kek = new byte[KEK_SIZE_BYTES];
        secureRandom.nextBytes(kek);
        kekStore.put(secretKekId, kek);

        logger.warn("⚠️  LocalDevKmsClient is active — in-memory KMS for unit tests only. " +
                    "Use KMS_PROVIDER=VAULT when running with docker-compose.");
    }

    @Override
    public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
        byte[] kek = kekStore.get(kekId);
        if (kek == null) {
            return Result.failure(KMSError.of("KEK_NOT_FOUND",
                    "KEK not found in local store: " + kekId));
        }
        try {
            byte[] encrypted = aesgcmEncrypt(dek.getKeyMaterial(), kek);
            return Result.success(EncryptedDEK.of(encrypted, kekId, "LOCAL_DEV"));
        } catch (Exception e) {
            return Result.failure(KMSError.of("ENCRYPT_FAILED", "DEK encryption failed: " + e.getMessage(), e));
        }
    }

    @Override
    public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
        byte[] kek = kekStore.get(kekId);
        if (kek == null) {
            return Result.failure(KMSError.of("KEK_NOT_FOUND",
                    "KEK not found in local store: " + kekId));
        }
        try {
            byte[] plaintext = aesgcmDecrypt(encryptedDEK.getCiphertext(), kek);
            return Result.success(DEK.of(plaintext));
        } catch (Exception e) {
            return Result.failure(KMSError.of("DECRYPT_FAILED", "DEK decryption failed: " + e.getMessage(), e));
        }
    }

    @Override
    public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
        UUID kekId = UUID.randomUUID();
        byte[] kek = new byte[KEK_SIZE_BYTES];
        secureRandom.nextBytes(kek);
        kekStore.put(kekId, kek);
        logger.debug("Generated local KEK {} for context={} env={}", kekId, context, environment);
        return Result.success(kekId);
    }

    @Override
    public Result<Unit, KMSError> deleteDEK(UUID keyId) {
        // In local dev, deletion is a no-op (no persistent store to clean up)
        logger.debug("LocalDevKmsClient: deleteDEK called for keyId={} (no-op)", keyId);
        return Result.success(Unit.unit());
    }

    @Override
    public Result<Unit, KMSError> storeSecret(UUID secretId, String secretValue, UUID kekId) {
        byte[] kek = kekStore.get(kekId);
        if (kek == null) {
            // Fall back to the internal secret KEK
            kek = kekStore.get(secretKekId);
        }
        try {
            byte[] encrypted = aesgcmEncrypt(secretValue.getBytes(java.nio.charset.StandardCharsets.UTF_8), kek);
            secretStore.put(secretId, encrypted);
            return Result.success(Unit.unit());
        } catch (Exception e) {
            return Result.failure(KMSError.of("STORE_SECRET_FAILED", "Secret storage failed: " + e.getMessage(), e));
        }
    }

    @Override
    public Result<String, KMSError> retrieveSecret(UUID secretId, UUID kekId) {
        byte[] encrypted = secretStore.get(secretId);
        if (encrypted == null) {
            return Result.failure(KMSError.of("SECRET_NOT_FOUND", "Secret not found: " + secretId));
        }
        byte[] kek = kekStore.get(kekId);
        if (kek == null) {
            kek = kekStore.get(secretKekId);
        }
        try {
            byte[] plaintext = aesgcmDecrypt(encrypted, kek);
            return Result.success(new String(plaintext, java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            return Result.failure(KMSError.of("RETRIEVE_SECRET_FAILED", "Secret retrieval failed: " + e.getMessage(), e));
        }
    }

    @Override
    public Result<Unit, KMSError> deleteSecret(UUID secretId) {
        secretStore.remove(secretId);
        return Result.success(Unit.unit());
    }

    @Override
    public Result<KMSHealth, KMSError> healthCheck() {
        return Result.success(KMSHealth.healthy(0L));
    }

    // -------------------------------------------------------------------------
    // AES-256-GCM helpers
    // -------------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with AES-256-GCM using the given KEK.
     * Output format: [12-byte IV][ciphertext+tag].
     */
    private byte[] aesgcmEncrypt(byte[] plaintext, byte[] kek) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKey key = new SecretKeySpec(kek, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = new byte[GCM_IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(ciphertext, 0, result, GCM_IV_LENGTH, ciphertext.length);
        return result;
    }

    /**
     * Decrypts data produced by {@link #aesgcmEncrypt}.
     * Input format: [12-byte IV][ciphertext+tag].
     */
    private byte[] aesgcmDecrypt(byte[] data, byte[] kek) throws Exception {
        if (data.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Encrypted data too short");
        }
        byte[] iv = Arrays.copyOfRange(data, 0, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(data, GCM_IV_LENGTH, data.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKey key = new SecretKeySpec(kek, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return cipher.doFinal(ciphertext);
    }
}
