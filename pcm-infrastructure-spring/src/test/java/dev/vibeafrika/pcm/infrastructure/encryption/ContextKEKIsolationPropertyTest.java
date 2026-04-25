package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for Context KEK Isolation.
 *
 * <p><b>Property 37: Context KEK Isolation</b>
 *
 * <p>For any two different bounded contexts, the active DEKs returned by
 * {@code getActiveDEK(contextA)} and {@code getActiveDEK(contextB)} must
 * reference different KEK IDs, proving that each bounded context uses its
 * own isolated KEK.
 *
 * <p>The Key_Manager SHALL maintain a separate KEK for each
 * Bounded_Context (Profile, Consent, Segment, Preference).
 */
class ContextKEKIsolationPropertyTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Property 37: Context KEK Isolation
     *
     * <p>For any two distinct bounded contexts, the KEK IDs used to encrypt their
     * respective active DEKs must be different. This guarantees that a compromise
     * of one context's KEK does not expose another context's DEKs.
     */
    @Property(tries = 200)
    @Label("Property 37: Different bounded contexts use different KEKs for their active DEKs")
    void differentContextsUseDifferentKEKsForTheirActiveDEKs(
            @ForAll("distinctContextPair") BoundedContext[] contextPair) {

        BoundedContext contextA = contextPair[0];
        BoundedContext contextB = contextPair[1];

        // Arrange: build a KeyManager backed by a stub KMS that generates unique KEKs per context
        StubKmsClient stubKms = new StubKmsClient();
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        DEKCache dekCache = new DEKCache();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        KeyManager keyManager = new KeyManager(stubKms, noOpAuditLogger, dekCache, Environment.DEV, ivCounter);
        keyManager.initializeBlindIndexKey();

        // Initialize KEKs for both contexts — each call generates a distinct KEK
        Result<UUID, KeyError> kekResultA = keyManager.initializeKEK(contextA);
        Result<UUID, KeyError> kekResultB = keyManager.initializeKEK(contextB);

        assertThat(kekResultA.isSuccess())
                .as("KEK initialization should succeed for context %s", contextA)
                .isTrue();
        assertThat(kekResultB.isSuccess())
                .as("KEK initialization should succeed for context %s", contextB)
                .isTrue();

        UUID kekIdA = kekResultA.getValue().orElseThrow();
        UUID kekIdB = kekResultB.getValue().orElseThrow();

        // The KEK IDs themselves must already be distinct
        assertThat(kekIdA)
                .as("KEK for context %s must differ from KEK for context %s ",
                        contextA, contextB)
                .isNotEqualTo(kekIdB);

        // Create active DEKs for both contexts
        Result<UUID, KeyError> dekResultA = keyManager.rotateDEK(contextA);
        Result<UUID, KeyError> dekResultB = keyManager.rotateDEK(contextB);

        assertThat(dekResultA.isSuccess())
                .as("DEK rotation should succeed for context %s", contextA)
                .isTrue();
        assertThat(dekResultB.isSuccess())
                .as("DEK rotation should succeed for context %s", contextB)
                .isTrue();

        // Retrieve the active DEKs and inspect their kekId metadata
        Result<DEKWithMetadata, KeyError> activeDEKA = keyManager.getActiveDEK(contextA);
        Result<DEKWithMetadata, KeyError> activeDEKB = keyManager.getActiveDEK(contextB);

        assertThat(activeDEKA.isSuccess())
                .as("getActiveDEK should succeed for context %s", contextA)
                .isTrue();
        assertThat(activeDEKB.isSuccess())
                .as("getActiveDEK should succeed for context %s", contextB)
                .isTrue();

        UUID activeDEKKekIdA = activeDEKA.getValue().orElseThrow().getKekId();
        UUID activeDEKKekIdB = activeDEKB.getValue().orElseThrow().getKekId();

        // Core property: the KEK IDs referenced by the active DEKs must be different
        assertThat(activeDEKKekIdA)
                .as("Active DEK for context %s must use a different KEK than active DEK for context %s "
                        + "(separate KEK per bounded context). "
                        + "kekId(%s)=%s, kekId(%s)=%s",
                        contextA, contextB, contextA, activeDEKKekIdA, contextB, activeDEKKekIdB)
                .isNotEqualTo(activeDEKKekIdB);
    }

    /**
     * Property 37 (all pairs): Verifies KEK isolation holds for every possible
     * pair of distinct bounded contexts exhaustively.
     */
    @Property(tries = 100)
    @Label("Property 37: All pairs of distinct bounded contexts use different KEKs")
    void allPairsOfDistinctContextsUseDifferentKEKs(
            @ForAll("distinctContextPair") BoundedContext[] contextPair) {

        BoundedContext contextA = contextPair[0];
        BoundedContext contextB = contextPair[1];

        StubKmsClient stubKms = new StubKmsClient();
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        DEKCache dekCache = new DEKCache();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        KeyManager keyManager = new KeyManager(stubKms, noOpAuditLogger, dekCache, Environment.PROD, ivCounter);
        keyManager.initializeBlindIndexKey();

        // Initialize all four contexts so the KeyManager has a complete KEK map
        for (BoundedContext ctx : BoundedContext.values()) {
            Result<UUID, KeyError> init = keyManager.initializeKEK(ctx);
            assertThat(init.isSuccess())
                    .as("KEK initialization must succeed for context %s", ctx)
                    .isTrue();
            Result<UUID, KeyError> dek = keyManager.rotateDEK(ctx);
            assertThat(dek.isSuccess())
                    .as("DEK rotation must succeed for context %s", ctx)
                    .isTrue();
        }

        // Retrieve active DEKs for the two contexts under test
        Result<DEKWithMetadata, KeyError> activeDEKA = keyManager.getActiveDEK(contextA);
        Result<DEKWithMetadata, KeyError> activeDEKB = keyManager.getActiveDEK(contextB);

        assertThat(activeDEKA.isSuccess()).isTrue();
        assertThat(activeDEKB.isSuccess()).isTrue();

        UUID kekIdA = activeDEKA.getValue().orElseThrow().getKekId();
        UUID kekIdB = activeDEKB.getValue().orElseThrow().getKekId();

        assertThat(kekIdA)
                .as("Context %s and context %s must use different KEKs. "
                        + "Got kekId(%s)=%s, kekId(%s)=%s",
                        contextA, contextB, contextA, kekIdA, contextB, kekIdB)
                .isNotEqualTo(kekIdB);
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    /**
     * Generates pairs of distinct {@link BoundedContext} values.
     *
     * <p>The generator picks two different contexts so that the property always
     * tests genuine cross-context isolation (never the same context against itself).
     */
    @Provide
    Arbitrary<BoundedContext[]> distinctContextPair() {
        BoundedContext[] all = BoundedContext.values();
        return Arbitraries.of(all).flatMap(contextA ->
                Arbitraries.of(all)
                        .filter(contextB -> contextB != contextA)
                        .map(contextB -> new BoundedContext[]{contextA, contextB})
        );
    }

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    /**
     * A stub {@link IKMSClient} that performs real AES-256-GCM DEK wrapping in
     * memory, without any external KMS dependency.
     *
     * <p>Each call to {@link #generateKEK} creates a fresh random KEK ID and stores
     * a random 256-bit KEK. {@link #encryptDEK} and {@link #decryptDEK} use AES-GCM
     * to wrap/unwrap the DEK bytes with the stored KEK material.
     *
     * <p>Because each {@code generateKEK} call produces a unique UUID, two different
     * contexts will always receive different KEK IDs — which is exactly the behaviour
     * we needed.
     */
    private static final class StubKmsClient implements IKMSClient {

        /** KEK ID → raw 256-bit KEK bytes */
        private final Map<UUID, byte[]> kekStore = new ConcurrentHashMap<>();

        @Override
        public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
            UUID kekId = UUID.randomUUID();
            byte[] kekBytes = new byte[32];
            SECURE_RANDOM.nextBytes(kekBytes);
            kekStore.put(kekId, kekBytes);
            return Result.success(kekId);
        }

        @Override
        public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
            byte[] kekBytes = kekStore.get(kekId);
            if (kekBytes == null) {
                return Result.failure(KMSError.of("KEK_NOT_FOUND", "KEK not found: " + kekId));
            }
            try {
                javax.crypto.SecretKey kek = new javax.crypto.spec.SecretKeySpec(kekBytes, "AES");
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                byte[] iv = new byte[12];
                SECURE_RANDOM.nextBytes(iv);
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, kek,
                        new javax.crypto.spec.GCMParameterSpec(128, iv));
                byte[] encryptedDEKBytes = cipher.doFinal(dek.getKeyMaterial());
                // Prepend IV so decryptDEK can recover it
                byte[] combined = new byte[iv.length + encryptedDEKBytes.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(encryptedDEKBytes, 0, combined, iv.length, encryptedDEKBytes.length);
                return Result.success(EncryptedDEK.of(combined, kekId));
            } catch (Exception e) {
                return Result.failure(KMSError.of("ENCRYPTION_FAILED", e.getMessage()));
            }
        }

        @Override
        public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
            byte[] kekBytes = kekStore.get(kekId);
            if (kekBytes == null) {
                return Result.failure(KMSError.of("KEK_NOT_FOUND", "KEK not found: " + kekId));
            }
            try {
                byte[] combined = encryptedDEK.getCiphertext();
                byte[] iv = new byte[12];
                System.arraycopy(combined, 0, iv, 0, 12);
                byte[] encryptedDEKBytes = new byte[combined.length - 12];
                System.arraycopy(combined, 12, encryptedDEKBytes, 0, encryptedDEKBytes.length);

                javax.crypto.SecretKey kek = new javax.crypto.spec.SecretKeySpec(kekBytes, "AES");
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, kek,
                        new javax.crypto.spec.GCMParameterSpec(128, iv));
                byte[] dekBytes = cipher.doFinal(encryptedDEKBytes);
                return Result.success(DEK.of(dekBytes));
            } catch (Exception e) {
                return Result.failure(KMSError.of("DECRYPTION_FAILED", e.getMessage()));
            }
        }

        @Override
        public Result<Unit, KMSError> deleteDEK(UUID keyId) {
            return Result.success(Unit.unit());
        }

        @Override
        public Result<KMSHealth, KMSError> healthCheck() {
            return Result.success(KMSHealth.healthy(0L));
        }

        @Override
        public Result<Unit, KMSError> storeSecret(java.util.UUID secretId, String secretValue, java.util.UUID kekId) {
            return Result.success(Unit.unit());
        }

        @Override
        public Result<String, KMSError> retrieveSecret(java.util.UUID secretId, java.util.UUID kekId) {
            return Result.failure(KMSError.of("NOT_IMPLEMENTED", "retrieveSecret not implemented in stub"));
        }

        @Override
        public Result<Unit, KMSError> deleteSecret(java.util.UUID secretId) {
            return Result.success(Unit.unit());
        }
    }

    /**
     * No-op {@link IAuditLogger} that discards all events.
     */
    private static final class NoOpAuditLogger implements IAuditLogger {

        private static final AuditError NOOP = AuditError.of("NOOP", "no-op logger");

        @Override
        public Result<Void, AuditError> logEncryption(EncryptionEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logDecryption(DecryptionEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logKeyRotation(KeyRotationEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logSecurityEvent(SecurityEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logKeyAccess(KeyAccessEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) {
            return Result.failure(NOOP);
        }
    }
}
