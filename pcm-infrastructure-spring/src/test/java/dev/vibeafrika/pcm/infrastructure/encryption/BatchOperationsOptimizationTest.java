package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests verifying that batch encryption/decryption operations minimise KMS calls.
 *
 * <p>Requirements 10.3, 10.4:
 * <ul>
 *   <li>encryptBatch reuses a single DEK for all items (one getActiveDEK call)</li>
 *   <li>decryptBatch pre-fetches unique DEKs — O(k) calls, not O(n)</li>
 *   <li>decryptBatch preserves input order</li>
 *   <li>empty batches are handled gracefully</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class BatchOperationsOptimizationTest {

    @Mock
    private IKeyManager keyManager;

    @Mock
    private IAuditLogger auditLogger;

    private EncryptionService service;

    @BeforeEach
    void setUp() {
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-salt");
        service = new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);

        // Audit logger is a no-op for these tests — EncryptionService ignores audit failures
        lenient().when(auditLogger.logEncryption(any()))
                .thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));
        lenient().when(auditLogger.logDecryption(any()))
                .thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));
        lenient().when(auditLogger.logSecurityEvent(any()))
                .thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));
    }

    // =========================================================================
    // encryptBatch — single DEK reuse
    // =========================================================================

    /**
     * Verifies that encryptBatch calls getActiveDEK exactly once regardless of batch size.
     * Requirements: 10.3, 10.4
     */
    @Test
    void encryptBatch_reusesDEKForAllItems() throws Exception {
        // Arrange
        UUID dekId = UUID.randomUUID();
        DEKWithMetadata dekMeta = buildDEKMetadata(dekId, BoundedContext.PROFILE);
        when(keyManager.getActiveDEK(BoundedContext.PROFILE)).thenReturn(Result.success(dekMeta));

        List<String> plaintexts = List.of("alice@example.com", "bob@example.com", "carol@example.com");

        // Act
        Result<List<Ciphertext>, EncryptionError> result =
                service.encryptBatch(plaintexts, BoundedContext.PROFILE);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getValue().orElseThrow()).hasSize(3);

        // getActiveDEK must be called exactly once — not once per item
        verify(keyManager, times(1)).getActiveDEK(BoundedContext.PROFILE);
    }

    // =========================================================================
    // decryptBatch — pre-fetch unique DEKs
    // =========================================================================

    /**
     * Verifies that decryptBatch calls getDEK exactly once per unique key ID,
     * even when the batch contains ciphertexts from multiple DEKs.
     * Requirements: 10.3, 10.4
     */
    @Test
    void decryptBatch_prefetchesUniqueDEKs() throws Exception {
        // Arrange: two different DEKs (simulating key rotation)
        UUID dekId1 = UUID.randomUUID();
        UUID dekId2 = UUID.randomUUID();
        DEKWithMetadata dek1Meta = buildDEKMetadata(dekId1, BoundedContext.PROFILE);
        DEKWithMetadata dek2Meta = buildDEKMetadata(dekId2, BoundedContext.PROFILE);

        // Encrypt 3 items with DEK1 and 2 items with DEK2
        when(keyManager.getActiveDEK(BoundedContext.PROFILE))
                .thenReturn(Result.success(dek1Meta))   // first encryptBatch call
                .thenReturn(Result.success(dek2Meta));  // second encryptBatch call

        List<String> batch1Plaintexts = List.of("alice@example.com", "bob@example.com", "carol@example.com");
        List<String> batch2Plaintexts = List.of("dave@example.com", "eve@example.com");

        Result<List<Ciphertext>, EncryptionError> enc1 =
                service.encryptBatch(batch1Plaintexts, BoundedContext.PROFILE);
        Result<List<Ciphertext>, EncryptionError> enc2 =
                service.encryptBatch(batch2Plaintexts, BoundedContext.PROFILE);

        assertThat(enc1.isSuccess()).isTrue();
        assertThat(enc2.isSuccess()).isTrue();

        // Build a mixed batch: 3 from DEK1, 2 from DEK2
        List<Ciphertext> mixedBatch = new ArrayList<>();
        mixedBatch.addAll(enc1.getValue().orElseThrow());
        mixedBatch.addAll(enc2.getValue().orElseThrow());

        // Set up getDEK to return the correct DEK for each key ID
        when(keyManager.getDEK(dekId1)).thenReturn(Result.success(dek1Meta));
        when(keyManager.getDEK(dekId2)).thenReturn(Result.success(dek2Meta));

        // Act
        Result<List<String>, DecryptionError> result =
                service.decryptBatch(mixedBatch, BoundedContext.PROFILE);

        // Assert: decryption succeeded
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getValue().orElseThrow()).hasSize(5);

        // getDEK must be called exactly 2 times (once per unique DEK), not 5 times
        verify(keyManager, times(1)).getDEK(dekId1);
        verify(keyManager, times(1)).getDEK(dekId2);
        verify(keyManager, times(2)).getDEK(any(UUID.class));
    }

    // =========================================================================
    // decryptBatch — order preservation
    // =========================================================================

    /**
     * Verifies that decryptBatch returns plaintexts in the same order as the input ciphertexts.
     * Requirements: 10.3
     */
    @Test
    void decryptBatch_preservesOrder() throws Exception {
        // Arrange
        UUID dekId = UUID.randomUUID();
        DEKWithMetadata dekMeta = buildDEKMetadata(dekId, BoundedContext.CONSENT);
        when(keyManager.getActiveDEK(BoundedContext.CONSENT)).thenReturn(Result.success(dekMeta));
        when(keyManager.getDEK(dekId)).thenReturn(Result.success(dekMeta));

        List<String> originalPlaintexts = List.of(
                "first@example.com",
                "second@example.com",
                "third@example.com",
                "fourth@example.com"
        );

        Result<List<Ciphertext>, EncryptionError> encResult =
                service.encryptBatch(originalPlaintexts, BoundedContext.CONSENT);
        assertThat(encResult.isSuccess()).isTrue();

        // Act
        Result<List<String>, DecryptionError> decResult =
                service.decryptBatch(encResult.getValue().orElseThrow(), BoundedContext.CONSENT);

        // Assert: order must be preserved
        assertThat(decResult.isSuccess()).isTrue();
        assertThat(decResult.getValue().orElseThrow())
                .containsExactlyElementsOf(originalPlaintexts);
    }

    // =========================================================================
    // decryptBatch — empty batch
    // =========================================================================

    /**
     * Verifies that decryptBatch handles an empty input list without errors.
     * Requirements: 10.3
     */
    @Test
    void decryptBatch_handlesEmptyBatch() {
        // Act
        Result<List<String>, DecryptionError> result =
                service.decryptBatch(List.of(), BoundedContext.PROFILE);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getValue().orElseThrow()).isEmpty();

        // No KMS calls should be made for an empty batch
        verifyNoInteractions(keyManager);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private DEKWithMetadata buildDEKMetadata(UUID keyId, BoundedContext context) {
        byte[] keyMaterial = new byte[32];
        new SecureRandom().nextBytes(keyMaterial);
        DEK dek = DEK.of(keyMaterial);
        return DEKWithMetadata.builder()
                .dek(dek)
                .keyId(keyId)
                .kekId(UUID.randomUUID())
                .context(context)
                .environment(Environment.DEV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now())
                .status(KeyStatus.ACTIVE)
                .build();
    }
}
