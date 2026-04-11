package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.infrastructure.encryption.entity.AuditLogEntryEntity;
import dev.vibeafrika.pcm.infrastructure.encryption.repository.AuditLogEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AuditLogStore}.
 *
 * <p>Verifies:
 * <ul>
 *   <li>Entries are encrypted at rest (ciphertext differs from plaintext)</li>
 *   <li>Encryption is non-deterministic (different IVs produce different ciphertexts)</li>
 *   <li>Decryption recovers the original plaintext</li>
 *   <li>Append-only: repository {@code save} is called, never {@code delete}</li>
 *   <li>Integrity verification passes for unmodified entries</li>
 *   <li>Integrity verification fails for tampered entries</li>
 *   <li>Invalid key length is rejected at construction time</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuditLogStoreTest {

    private static final byte[] VALID_KEY = new byte[32]; // 256-bit key

    static {
        new SecureRandom().nextBytes(VALID_KEY);
    }

    @Mock
    private AuditLogEntryRepository repository;

    private AuditLogStore store;

    @BeforeEach
    void setUp() {
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        store = new AuditLogStore(repository, VALID_KEY);
    }

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    @Test
    void constructor_rejectsNullKey() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuditLogStore(repository, null));
    }

    @Test
    void constructor_rejectsShortKey() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuditLogStore(repository, new byte[16]));
    }

    @Test
    void constructor_rejectsLongKey() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuditLogStore(repository, new byte[64]));
    }

    // -------------------------------------------------------------------------
    // Encryption at rest
    // -------------------------------------------------------------------------

    @Test
    void encrypt_producesNonPlaintextOutput() throws Exception {
        String plaintext = "{\"eventType\":\"ENCRYPTION\",\"success\":true}";
        byte[] encrypted = store.encrypt(plaintext);

        // The encrypted bytes must not equal the plaintext bytes
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        assertFalse(Arrays.equals(plaintextBytes, encrypted),
                "Encrypted output must differ from plaintext");
    }

    @Test
    void encrypt_decryptRoundTrip() throws Exception {
        String plaintext = "{\"eventType\":\"DECRYPTION\",\"context\":\"PROFILE\"}";
        byte[] encrypted = store.encrypt(plaintext);
        String decrypted = store.decrypt(encrypted);

        assertEquals(plaintext, decrypted, "Decrypted text must equal original plaintext");
    }

    @Test
    void encrypt_differentIVsProduceDifferentCiphertexts() throws Exception {
        String plaintext = "same plaintext";
        byte[] ct1 = store.encrypt(plaintext);
        byte[] ct2 = store.encrypt(plaintext);

        assertFalse(Arrays.equals(ct1, ct2),
                "Two encryptions of the same plaintext must produce different ciphertexts");
    }

    @Test
    void decrypt_detectsTampering() throws Exception {
        String plaintext = "audit entry";
        byte[] encrypted = store.encrypt(plaintext);

        // Flip a byte in the ciphertext portion (after the 12-byte IV)
        encrypted[20] ^= 0xFF;

        assertThrows(Exception.class, () -> store.decrypt(encrypted),
                "Tampered ciphertext must cause decryption to fail");
    }

    @Test
    void decrypt_rejectsTooShortPayload() {
        assertThrows(IllegalArgumentException.class,
                () -> store.decrypt(new byte[5]));
    }

    // -------------------------------------------------------------------------
    // Append-only storage
    // -------------------------------------------------------------------------

    @Test
    void append_callsRepositorySave() {
        String plaintext = "{\"eventType\":\"KEY_ROTATION\"}";
        boolean result = store.append("KEY_ROTATION", Instant.now(), plaintext, "abc123");

        assertTrue(result);
        verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
    }

    @Test
    void append_storesEncryptedPayload() {
        ArgumentCaptor<AuditLogEntryEntity> captor =
                ArgumentCaptor.forClass(AuditLogEntryEntity.class);

        String plaintext = "{\"eventType\":\"ENCRYPTION\",\"success\":true}";
        store.append("ENCRYPTION", Instant.now(), plaintext, "sig123");

        verify(repository).save(captor.capture());
        AuditLogEntryEntity saved = captor.getValue();

        // The stored payload must not equal the plaintext bytes
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        assertFalse(Arrays.equals(plaintextBytes, saved.getEncryptedPayload()),
                "Stored payload must be encrypted, not plaintext");
    }

    @Test
    void append_storesHmacSignature() {
        ArgumentCaptor<AuditLogEntryEntity> captor =
                ArgumentCaptor.forClass(AuditLogEntryEntity.class);

        store.append("SECURITY_EVENT", Instant.now(), "payload", "expected-sig");

        verify(repository).save(captor.capture());
        assertEquals("expected-sig", captor.getValue().getHmacSignature());
    }

    @Test
    void append_storesCorrectEventType() {
        ArgumentCaptor<AuditLogEntryEntity> captor =
                ArgumentCaptor.forClass(AuditLogEntryEntity.class);

        store.append("KEY_ACCESS", Instant.now(), "payload", "sig");

        verify(repository).save(captor.capture());
        assertEquals("KEY_ACCESS", captor.getValue().getEventType());
    }

    @Test
    void append_incrementsSequenceNumber() {
        ArgumentCaptor<AuditLogEntryEntity> captor =
                ArgumentCaptor.forClass(AuditLogEntryEntity.class);

        store.append("ENCRYPTION", Instant.now(), "p1", "s1");
        store.append("DECRYPTION", Instant.now(), "p2", "s2");

        verify(repository, times(2)).save(captor.capture());
        long seq1 = captor.getAllValues().get(0).getSequenceNumber();
        long seq2 = captor.getAllValues().get(1).getSequenceNumber();
        assertTrue(seq2 > seq1, "Sequence numbers must be strictly increasing");
    }

    @Test
    void append_returnsFalseOnRepositoryException() {
        when(repository.save(any())).thenThrow(new RuntimeException("DB error"));

        boolean result = store.append("ENCRYPTION", Instant.now(), "payload", "sig");

        assertFalse(result, "append must return false when repository throws");
    }

    // -------------------------------------------------------------------------
    // Integrity verification
    // -------------------------------------------------------------------------

    @Test
    void verifyIntegrity_passesForUnmodifiedEntry() throws Exception {
        String plaintext = "{\"eventType\":\"ENCRYPTION\"}";
        byte[] encrypted = store.encrypt(plaintext);
        String sig = "correct-sig";

        AuditLogEntryEntity entity = new AuditLogEntryEntity(1L, "ENCRYPTION",
                Instant.now(), encrypted, sig);

        // Verifier that always returns the stored signature for the correct plaintext
        boolean valid = store.verifyIntegrity(entity, payload -> {
            assertEquals(plaintext, payload);
            return sig;
        });

        assertTrue(valid, "Integrity check must pass for unmodified entry");
    }

    @Test
    void verifyIntegrity_failsForTamperedSignature() throws Exception {
        String plaintext = "{\"eventType\":\"ENCRYPTION\"}";
        byte[] encrypted = store.encrypt(plaintext);

        AuditLogEntryEntity entity = new AuditLogEntryEntity(1L, "ENCRYPTION",
                Instant.now(), encrypted, "correct-sig");

        // Verifier returns a different signature
        boolean valid = store.verifyIntegrity(entity, payload -> "wrong-sig");

        assertFalse(valid, "Integrity check must fail when signatures differ");
    }

    @Test
    void verifyIntegrity_failsForTamperedPayload() throws Exception {
        String plaintext = "original payload";
        byte[] encrypted = store.encrypt(plaintext);

        // Tamper with the ciphertext
        encrypted[15] ^= 0xFF;

        AuditLogEntryEntity entity = new AuditLogEntryEntity(1L, "ENCRYPTION",
                Instant.now(), encrypted, "sig");

        boolean valid = store.verifyIntegrity(entity, payload -> "sig");

        assertFalse(valid, "Integrity check must fail when ciphertext is tampered");
    }
}
