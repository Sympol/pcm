package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for blind index searchability.
 *
 * <p><b>Property 14: Blind Index Searchability</b>
 *
 * <p><b>Validates: Requirements 6.2</b>
 *
 * <p>For any plaintext value and its blind index, searching by the blind index shall
 * return records containing that plaintext value. Concretely:
 * <ul>
 *   <li>Same plaintext + same salt → same blind index (determinism / searchability)</li>
 *   <li>Different plaintexts + same salt → different blind indexes (no false positives)</li>
 *   <li>Normalization is consistent: case and surrounding whitespace do not affect matching</li>
 * </ul>
 */
class BlindIndexSearchabilityPropertyTest {

    // -------------------------------------------------------------------------
    // Property 14a: Determinism — same plaintext + same salt → same blind index
    // -------------------------------------------------------------------------

    /**
     * Property 14a: For any plaintext and record salt, generating the blind index twice
     * must produce the same value. This is the core searchability guarantee: a stored
     * blind index can be reproduced at query time to find the matching record.
     *
     * <p><b>Validates: Requirements 6.2</b>
     */
    @Property(tries = 300)
    @Label("Property 14a: Same plaintext and salt always produce the same blind index")
    void samePlaintextAndSaltProduceSameBlindIndex(
            @ForAll("searchablePlaintext") String plaintext,
            @ForAll("recordSalt") String recordSalt) {

        BlindIndexService service = buildBlindIndexService();

        Result<BlindIndex, EncryptionError> first = service.generateBlindIndex(plaintext, recordSalt);
        Result<BlindIndex, EncryptionError> second = service.generateBlindIndex(plaintext, recordSalt);

        assertThat(first.isSuccess())
                .as("First blind index generation for '%s' should succeed", plaintext)
                .isTrue();
        assertThat(second.isSuccess())
                .as("Second blind index generation for '%s' should succeed", plaintext)
                .isTrue();

        assertThat(first.getValue().orElseThrow().getValue())
                .as("Blind index must be deterministic: same plaintext + salt must produce same index")
                .isEqualTo(second.getValue().orElseThrow().getValue());
    }

    // -------------------------------------------------------------------------
    // Property 14b: No false positives — different plaintexts → different indexes
    // -------------------------------------------------------------------------

    /**
     * Property 14b: For any two distinct plaintext values with the same record salt,
     * their blind indexes must differ. This ensures that searching by a blind index
     * does not return records with different plaintext values.
     *
     * <p><b>Validates: Requirements 6.2</b>
     */
    @Property(tries = 200)
    @Label("Property 14b: Different plaintexts with same salt produce different blind indexes")
    void differentPlaintextsProduceDifferentBlindIndexes(
            @ForAll("searchablePlaintext") String plaintext,
            @ForAll("recordSalt") String recordSalt) {

        BlindIndexService service = buildBlindIndexService();

        // Create a clearly different plaintext by appending a distinguishing suffix
        String differentPlaintext = plaintext + "_different_value_xyz";

        Result<BlindIndex, EncryptionError> indexForOriginal =
                service.generateBlindIndex(plaintext, recordSalt);
        Result<BlindIndex, EncryptionError> indexForDifferent =
                service.generateBlindIndex(differentPlaintext, recordSalt);

        assertThat(indexForOriginal.isSuccess()).isTrue();
        assertThat(indexForDifferent.isSuccess()).isTrue();

        assertThat(indexForOriginal.getValue().orElseThrow().getValue())
                .as("Blind index for '%s' must differ from blind index for '%s'",
                        plaintext, differentPlaintext)
                .isNotEqualTo(indexForDifferent.getValue().orElseThrow().getValue());
    }

    // -------------------------------------------------------------------------
    // Property 14c: Normalization consistency — case-insensitive matching
    // -------------------------------------------------------------------------

    /**
     * Property 14c: For any plaintext, the blind index generated from the original
     * value must equal the blind index generated from its uppercase variant.
     * This ensures that searching by email is case-insensitive, as required by
     * the normalization (lowercase + trim) applied inside BlindIndexService.
     *
     * <p><b>Validates: Requirements 6.2</b>
     */
    @Property(tries = 200)
    @Label("Property 14c: Blind index is case-insensitive (normalization is consistent)")
    void blindIndexIsCaseInsensitive(
            @ForAll("searchablePlaintext") String plaintext,
            @ForAll("recordSalt") String recordSalt) {

        BlindIndexService service = buildBlindIndexService();

        String upperCasePlaintext = plaintext.toUpperCase();

        Result<BlindIndex, EncryptionError> indexForOriginal =
                service.generateBlindIndex(plaintext, recordSalt);
        Result<BlindIndex, EncryptionError> indexForUpperCase =
                service.generateBlindIndex(upperCasePlaintext, recordSalt);

        assertThat(indexForOriginal.isSuccess()).isTrue();
        assertThat(indexForUpperCase.isSuccess()).isTrue();

        assertThat(indexForOriginal.getValue().orElseThrow().getValue())
                .as("Blind index for '%s' must equal blind index for its uppercase variant '%s' "
                        + "(normalization must be consistent)",
                        plaintext, upperCasePlaintext)
                .isEqualTo(indexForUpperCase.getValue().orElseThrow().getValue());
    }

    // -------------------------------------------------------------------------
    // Property 14d: Whitespace trimming — leading/trailing spaces do not affect match
    // -------------------------------------------------------------------------

    /**
     * Property 14d: For any plaintext, the blind index generated from the original
     * value must equal the blind index generated from a version with leading/trailing
     * whitespace added. This ensures that search queries with accidental whitespace
     * still find the correct record.
     *
     * <p><b>Validates: Requirements 6.2</b>
     */
    @Property(tries = 200)
    @Label("Property 14d: Blind index ignores leading/trailing whitespace (trim normalization)")
    void blindIndexIgnoresLeadingTrailingWhitespace(
            @ForAll("searchablePlaintext") String plaintext,
            @ForAll("recordSalt") String recordSalt) {

        BlindIndexService service = buildBlindIndexService();

        String paddedPlaintext = "  " + plaintext + "  ";

        Result<BlindIndex, EncryptionError> indexForOriginal =
                service.generateBlindIndex(plaintext, recordSalt);
        Result<BlindIndex, EncryptionError> indexForPadded =
                service.generateBlindIndex(paddedPlaintext, recordSalt);

        assertThat(indexForOriginal.isSuccess()).isTrue();
        assertThat(indexForPadded.isSuccess()).isTrue();

        assertThat(indexForOriginal.getValue().orElseThrow().getValue())
                .as("Blind index for '%s' must equal blind index for padded variant '%s' "
                        + "(trim normalization must be consistent)",
                        plaintext, paddedPlaintext)
                .isEqualTo(indexForPadded.getValue().orElseThrow().getValue());
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    /**
     * Generates PII-like plaintext values suitable for blind index searchability tests:
     * emails, names, and general lowercase ASCII strings.
     */
    @Provide
    Arbitrary<String> searchablePlaintext() {
        Arbitrary<String> emails = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(10),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(5)
        ).as((user, domain, tld) -> user.toLowerCase() + "@" + domain.toLowerCase() + "." + tld.toLowerCase());

        Arbitrary<String> names = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(15),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(15)
        ).as((first, last) -> first.toLowerCase() + " " + last.toLowerCase());

        Arbitrary<String> general = Arbitraries.strings()
                .withCharRange('a', 'z')
                .ofMinLength(1)
                .ofMaxLength(100);

        return Arbitraries.oneOf(emails, names, general);
    }

    /**
     * Generates per-record salt values (non-empty strings).
     */
    @Provide
    Arbitrary<String> recordSalt() {
        return Arbitraries.strings()
                .withCharRange('a', 'z')
                .ofMinLength(8)
                .ofMaxLength(32);
    }

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    /**
     * Builds a self-contained BlindIndexService with a fixed blind index key.
     * Using a fixed key ensures determinism within a single test run.
     */
    private BlindIndexService buildBlindIndexService() {
        return new BlindIndexService(new FixedBlindIndexKeyManager(), "test-global-salt-for-searchability");
    }

    /**
     * Minimal IKeyManager stub that returns a fixed blind index key.
     * The key is fixed per instance so blind index generation is deterministic.
     */
    private static final class FixedBlindIndexKeyManager implements IKeyManager {

        private static final byte[] FIXED_BLIND_INDEX_KEY;

        static {
            FIXED_BLIND_INDEX_KEY = new byte[32];
            new SecureRandom().nextBytes(FIXED_BLIND_INDEX_KEY);
        }

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            return Result.success(FIXED_BLIND_INDEX_KEY);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index test"));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index test"));
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index test"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index test"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index test"));
        }
    }
}
