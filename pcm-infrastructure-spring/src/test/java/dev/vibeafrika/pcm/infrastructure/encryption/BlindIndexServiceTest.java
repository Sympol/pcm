package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link BlindIndexService}.
 *
 * <p>Validates Requirements:
 * <ul>
 *   <li>THE Encryption_Service SHALL generate blind indexes using HMAC-SHA256
 *       with a separate blind index key</li>
 *   <li>THE Encryption_Service SHALL use a secret global salt with the blind
 *       index key to resist frequency analysis attacks</li>
 *   <li>THE Encryption_Service SHALL use a secret per-record salt with the
 *       blind index key to resist pattern matching attacks</li>
 * </ul>
 */
class BlindIndexServiceTest {

    private static final String GLOBAL_SALT = "test-global-salt-unit-tests";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /** Fixed 256-bit blind index key shared across all tests in this class. */
    private static final byte[] BLIND_INDEX_KEY;

    static {
        BLIND_INDEX_KEY = new byte[32];
        new SecureRandom().nextBytes(BLIND_INDEX_KEY);
    }

    private BlindIndexService service;

    @BeforeEach
    void setUp() {
        service = new BlindIndexService(new FixedBlindIndexKeyManager(), GLOBAL_SALT);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Blind index generation with various inputs
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class VariousInputs {

        @Test
        void generatesBlindIndexForEmail() {
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("user@example.com", "salt-abc");

            assertTrue(result.isSuccess(), "Should succeed for a standard email");
            assertNotNull(result.getValue().orElseThrow().getValue());
            assertFalse(result.getValue().orElseThrow().getValue().isBlank());
        }

        @Test
        void generatesBlindIndexForPhoneNumber() {
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("+1-800-555-0199", "salt-phone");

            assertTrue(result.isSuccess(), "Should succeed for a phone number");
            assertFalse(result.getValue().orElseThrow().getValue().isBlank());
        }

        @Test
        void generatesBlindIndexForName() {
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("Jane Doe", "salt-name");

            assertTrue(result.isSuccess(), "Should succeed for a full name");
            assertFalse(result.getValue().orElseThrow().getValue().isBlank());
        }

        @Test
        void generatesBlindIndexForSpecialCharacters() {
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("user+tag@example.co.uk", "salt-special");

            assertTrue(result.isSuccess(), "Should succeed for special characters");
            assertFalse(result.getValue().orElseThrow().getValue().isBlank());
        }

        @Test
        void generatesBlindIndexForUnicodeInput() {
            // Unicode name with accented characters
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("Ångström Müller", "salt-unicode");

            assertTrue(result.isSuccess(), "Should succeed for unicode input");
            assertFalse(result.getValue().orElseThrow().getValue().isBlank());
        }

        @Test
        void generatesBlindIndexForEmptyString() {
            // Empty string is a valid (if unusual) input — service should handle it
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("", "salt-empty");

            assertTrue(result.isSuccess(), "Should succeed for empty string input");
            assertFalse(result.getValue().orElseThrow().getValue().isBlank());
        }

        @Test
        void generatesBlindIndexForLongInput() {
            String longInput = "a".repeat(10_000);
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex(longInput, "salt-long");

            assertTrue(result.isSuccess(), "Should succeed for very long input");
            assertFalse(result.getValue().orElseThrow().getValue().isBlank());
        }

        /**
         * Validates Requirement : output is 64 hex characters (32 bytes = HMAC-SHA256 output).
         */
        @Test
        void outputIs64HexCharacters() {
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("test@example.com", "salt-len");

            assertTrue(result.isSuccess());
            String value = result.getValue().orElseThrow().getValue();
            assertEquals(64, value.length(),
                    "HMAC-SHA256 output must be 32 bytes = 64 hex characters");
            assertTrue(value.matches("[0-9a-f]+"),
                    "Output must be a lowercase hex string");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Normalization: case-insensitive and trimming
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class Normalization {

        @Test
        void uppercaseAndLowercaseProduceSameBlindIndex() {
            String recordSalt = "salt-case";
            Result<BlindIndex, EncryptionError> lower =
                    service.generateBlindIndex("user@example.com", recordSalt);
            Result<BlindIndex, EncryptionError> upper =
                    service.generateBlindIndex("USER@EXAMPLE.COM", recordSalt);

            assertTrue(lower.isSuccess());
            assertTrue(upper.isSuccess());
            assertEquals(lower.getValue().orElseThrow().getValue(),
                    upper.getValue().orElseThrow().getValue(),
                    "Uppercase and lowercase inputs must produce the same blind index (case-insensitive normalization)");
        }

        @Test
        void mixedCaseProducesSameBlindIndexAsLowercase() {
            String recordSalt = "salt-mixed";
            Result<BlindIndex, EncryptionError> lower =
                    service.generateBlindIndex("jane doe", recordSalt);
            Result<BlindIndex, EncryptionError> mixed =
                    service.generateBlindIndex("Jane Doe", recordSalt);

            assertTrue(lower.isSuccess());
            assertTrue(mixed.isSuccess());
            assertEquals(lower.getValue().orElseThrow().getValue(),
                    mixed.getValue().orElseThrow().getValue(),
                    "Mixed-case input must produce the same blind index as lowercase");
        }

        @Test
        void leadingWhitespaceIsStripped() {
            String recordSalt = "salt-trim-lead";
            Result<BlindIndex, EncryptionError> noSpace =
                    service.generateBlindIndex("user@example.com", recordSalt);
            Result<BlindIndex, EncryptionError> leadingSpace =
                    service.generateBlindIndex("   user@example.com", recordSalt);

            assertTrue(noSpace.isSuccess());
            assertTrue(leadingSpace.isSuccess());
            assertEquals(noSpace.getValue().orElseThrow().getValue(),
                    leadingSpace.getValue().orElseThrow().getValue(),
                    "Leading whitespace must be stripped before indexing");
        }

        @Test
        void trailingWhitespaceIsStripped() {
            String recordSalt = "salt-trim-trail";
            Result<BlindIndex, EncryptionError> noSpace =
                    service.generateBlindIndex("user@example.com", recordSalt);
            Result<BlindIndex, EncryptionError> trailingSpace =
                    service.generateBlindIndex("user@example.com   ", recordSalt);

            assertTrue(noSpace.isSuccess());
            assertTrue(trailingSpace.isSuccess());
            assertEquals(noSpace.getValue().orElseThrow().getValue(),
                    trailingSpace.getValue().orElseThrow().getValue(),
                    "Trailing whitespace must be stripped before indexing");
        }

        @Test
        void bothLeadingAndTrailingWhitespaceIsStripped() {
            String recordSalt = "salt-trim-both";
            Result<BlindIndex, EncryptionError> noSpace =
                    service.generateBlindIndex("user@example.com", recordSalt);
            Result<BlindIndex, EncryptionError> padded =
                    service.generateBlindIndex("  user@example.com  ", recordSalt);

            assertTrue(noSpace.isSuccess());
            assertTrue(padded.isSuccess());
            assertEquals(noSpace.getValue().orElseThrow().getValue(),
                    padded.getValue().orElseThrow().getValue(),
                    "Both leading and trailing whitespace must be stripped before indexing");
        }

        @Test
        void normalizationCombinesCaseAndTrim() {
            String recordSalt = "salt-combined";
            Result<BlindIndex, EncryptionError> canonical =
                    service.generateBlindIndex("user@example.com", recordSalt);
            Result<BlindIndex, EncryptionError> messy =
                    service.generateBlindIndex("  USER@EXAMPLE.COM  ", recordSalt);

            assertTrue(canonical.isSuccess());
            assertTrue(messy.isSuccess());
            assertEquals(canonical.getValue().orElseThrow().getValue(),
                    messy.getValue().orElseThrow().getValue(),
                    "Combined case + trim normalization must produce the same blind index");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Global salt usage
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class GlobalSaltUsage {

        /**
         * Validates Requirement: same plaintext + same record salt but different
         * global salt must produce a different blind index.
         */
        @Test
        void differentGlobalSaltProducesDifferentBlindIndex() {
            BlindIndexService serviceA =
                    new BlindIndexService(new FixedBlindIndexKeyManager(), "global-salt-alpha");
            BlindIndexService serviceB =
                    new BlindIndexService(new FixedBlindIndexKeyManager(), "global-salt-beta");

            String plaintext = "user@example.com";
            String recordSalt = "same-record-salt";

            Result<BlindIndex, EncryptionError> indexA = serviceA.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> indexB = serviceB.generateBlindIndex(plaintext, recordSalt);

            assertTrue(indexA.isSuccess());
            assertTrue(indexB.isSuccess());
            assertNotEquals(indexA.getValue().orElseThrow().getValue(),
                    indexB.getValue().orElseThrow().getValue(),
                    "Different global salts must produce different blind indexes");
        }

        @Test
        void sameGlobalSaltProducesSameBlindIndex() {
            // Two service instances with the same global salt and key must agree
            BlindIndexService serviceA =
                    new BlindIndexService(new FixedBlindIndexKeyManager(), GLOBAL_SALT);
            BlindIndexService serviceB =
                    new BlindIndexService(new FixedBlindIndexKeyManager(), GLOBAL_SALT);

            String plaintext = "user@example.com";
            String recordSalt = "same-record-salt";

            Result<BlindIndex, EncryptionError> indexA = serviceA.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> indexB = serviceB.generateBlindIndex(plaintext, recordSalt);

            assertTrue(indexA.isSuccess());
            assertTrue(indexB.isSuccess());
            assertEquals(indexA.getValue().orElseThrow().getValue(),
                    indexB.getValue().orElseThrow().getValue(),
                    "Same global salt must produce the same blind index for identical inputs");
        }

        @Test
        void globalSaltIsIncludedInHmacMessage() throws Exception {
            // Verify the global salt is part of the HMAC message by independently computing
            // the expected value and confirming it matches the service output.
            String plaintext = "user@example.com";
            String recordSalt = "record-salt-gs";

            Result<BlindIndex, EncryptionError> result = service.generateBlindIndex(plaintext, recordSalt);
            assertTrue(result.isSuccess());

            // Independently compute: HMAC-SHA256(key, globalSalt || recordSalt || normalize(plaintext))
            String normalized = plaintext.trim().toLowerCase();
            String message = GLOBAL_SALT + recordSalt + normalized;
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(BLIND_INDEX_KEY, HMAC_ALGORITHM));
            byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            String expected = HexFormat.of().formatHex(hmacBytes);

            assertEquals(expected, result.getValue().orElseThrow().getValue(),
                    "Blind index must equal HMAC-SHA256(key, globalSalt || recordSalt || normalize(plaintext))");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Per-record salt uniqueness
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class PerRecordSaltUniqueness {

        /**
         * Validates Requirement: same plaintext with different per-record salts
         * must produce different blind indexes.
         */
        @Test
        void differentRecordSaltsProduceDifferentBlindIndexes() {
            String plaintext = "user@example.com";

            Result<BlindIndex, EncryptionError> index1 =
                    service.generateBlindIndex(plaintext, "record-salt-001");
            Result<BlindIndex, EncryptionError> index2 =
                    service.generateBlindIndex(plaintext, "record-salt-002");

            assertTrue(index1.isSuccess());
            assertTrue(index2.isSuccess());
            assertNotEquals(index1.getValue().orElseThrow().getValue(),
                    index2.getValue().orElseThrow().getValue(),
                    "Different per-record salts must produce different blind indexes");
        }

        @Test
        void sameRecordSaltProducesSameBlindIndex() {
            String plaintext = "user@example.com";
            String recordSalt = "stable-record-salt";

            Result<BlindIndex, EncryptionError> index1 =
                    service.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> index2 =
                    service.generateBlindIndex(plaintext, recordSalt);

            assertTrue(index1.isSuccess());
            assertTrue(index2.isSuccess());
            assertEquals(index1.getValue().orElseThrow().getValue(),
                    index2.getValue().orElseThrow().getValue(),
                    "Same per-record salt must produce the same blind index for identical inputs");
        }

        @Test
        void multipleDistinctRecordSaltsAllProduceDifferentIndexes() {
            String plaintext = "shared@example.com";
            String[] salts = {"salt-A", "salt-B", "salt-C", "salt-D", "salt-E"};
            String[] indexes = new String[salts.length];

            for (int i = 0; i < salts.length; i++) {
                Result<BlindIndex, EncryptionError> result =
                        service.generateBlindIndex(plaintext, salts[i]);
                assertTrue(result.isSuccess(), "Should succeed for salt: " + salts[i]);
                indexes[i] = result.getValue().orElseThrow().getValue();
            }

            // All indexes must be distinct
            for (int i = 0; i < indexes.length; i++) {
                for (int j = i + 1; j < indexes.length; j++) {
                    assertNotEquals(indexes[i], indexes[j],
                            "Blind indexes for salts[" + i + "] and salts[" + j + "] must differ");
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Determinism
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class Determinism {

        @Test
        void sameInputsAlwaysProduceSameBlindIndex() {
            String plaintext = "deterministic@example.com";
            String recordSalt = "deterministic-salt";

            Result<BlindIndex, EncryptionError> first =
                    service.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> second =
                    service.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> third =
                    service.generateBlindIndex(plaintext, recordSalt);

            assertTrue(first.isSuccess());
            assertTrue(second.isSuccess());
            assertTrue(third.isSuccess());

            String value = first.getValue().orElseThrow().getValue();
            assertEquals(value, second.getValue().orElseThrow().getValue(),
                    "Same inputs must always produce the same blind index (determinism)");
            assertEquals(value, third.getValue().orElseThrow().getValue(),
                    "Same inputs must always produce the same blind index (determinism)");
        }

        @Test
        void deterministicAcrossMultipleServiceInstances() {
            String plaintext = "user@example.com";
            String recordSalt = "shared-salt";

            BlindIndexService instance1 =
                    new BlindIndexService(new FixedBlindIndexKeyManager(), GLOBAL_SALT);
            BlindIndexService instance2 =
                    new BlindIndexService(new FixedBlindIndexKeyManager(), GLOBAL_SALT);

            Result<BlindIndex, EncryptionError> index1 =
                    instance1.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> index2 =
                    instance2.generateBlindIndex(plaintext, recordSalt);

            assertTrue(index1.isSuccess());
            assertTrue(index2.isSuccess());
            assertEquals(index1.getValue().orElseThrow().getValue(),
                    index2.getValue().orElseThrow().getValue(),
                    "Different service instances with same key and salts must produce the same blind index");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. HMAC-SHA256 algorithm verification
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class HmacSha256Algorithm {

        /**
         * Validates Requirement: output length is 32 bytes / 64 hex chars.
         */
        @Test
        void outputLengthIs64HexChars() {
            String[] inputs = {
                "a", "user@example.com", "+1-800-555-0199", "Jane Doe",
                "Ångström", "x".repeat(1000)
            };

            for (String input : inputs) {
                Result<BlindIndex, EncryptionError> result =
                        service.generateBlindIndex(input, "salt-len-check");
                assertTrue(result.isSuccess(), "Should succeed for input: " + input);
                assertEquals(64, result.getValue().orElseThrow().getValue().length(),
                        "HMAC-SHA256 output must be 64 hex chars (32 bytes) for input: " + input);
            }
        }

        @Test
        void outputIsLowercaseHexString() {
            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex("test@example.com", "salt-hex");

            assertTrue(result.isSuccess());
            String value = result.getValue().orElseThrow().getValue();
            assertTrue(value.matches("[0-9a-f]{64}"),
                    "Output must be a 64-character lowercase hex string");
        }

        @Test
        void outputMatchesIndependentlyComputedHmacSha256() throws Exception {
            String plaintext = "verify@example.com";
            String recordSalt = "verify-salt";

            Result<BlindIndex, EncryptionError> result =
                    service.generateBlindIndex(plaintext, recordSalt);
            assertTrue(result.isSuccess());

            // Independently compute HMAC-SHA256(key, globalSalt || recordSalt || normalize(plaintext))
            String normalized = plaintext.trim().toLowerCase();
            String message = GLOBAL_SALT + recordSalt + normalized;
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(BLIND_INDEX_KEY, HMAC_ALGORITHM));
            byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            String expected = HexFormat.of().formatHex(hmacBytes);

            assertEquals(expected, result.getValue().orElseThrow().getValue(),
                    "Blind index must match independently computed HMAC-SHA256 (Req 6.3)");
        }

        @Test
        void differentPlaintextsProduceDifferentOutputs() {
            String recordSalt = "same-salt";
            Result<BlindIndex, EncryptionError> index1 =
                    service.generateBlindIndex("alice@example.com", recordSalt);
            Result<BlindIndex, EncryptionError> index2 =
                    service.generateBlindIndex("bob@example.com", recordSalt);

            assertTrue(index1.isSuccess());
            assertTrue(index2.isSuccess());
            assertNotEquals(index1.getValue().orElseThrow().getValue(),
                    index2.getValue().orElseThrow().getValue(),
                    "Different plaintexts must produce different blind indexes");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test infrastructure
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Minimal IKeyManager stub that returns the shared fixed blind index key.
     */
    private static final class FixedBlindIndexKeyManager implements IKeyManager {

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            byte[] copy = new byte[BLIND_INDEX_KEY.length];
            System.arraycopy(BLIND_INDEX_KEY, 0, copy, 0, copy.length);
            return Result.success(copy);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index unit test"));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index unit test"));
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index unit test"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index unit test"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index unit test"));
        }
    }
}
