package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based test for blind index salt uniqueness.
 *
 * <p><b>Property 16: Blind Index Salt Uniqueness</b>
 *
 * <p>For any identical plaintext value, generating blind indexes with two different
 * per-record salts must produce two different blind index values. This validates that
 * the blind index implementation uses per-record salts correctly to resist pattern
 * matching attacks and that the global salt contributes to
 * frequency analysis resistance.
 */
class BlindIndexSaltUniquenessPropertyTest {

    private static final String GLOBAL_SALT = "test-global-salt-for-salt-uniqueness";

    // -------------------------------------------------------------------------
    // Property 16: Identical plaintexts with different salts → different indexes
    // -------------------------------------------------------------------------

    /**
     * Property 16: For any plaintext and two distinct per-record salts, the blind
     * indexes produced must differ. This ensures that an attacker who observes
     * multiple blind indexes for the same plaintext value (e.g., the same email
     * stored in different records) cannot correlate them via pattern matching.
     */
    @Property(tries = 300)
    @Label("Property 16: Identical plaintexts with different per-record salts produce different blind indexes")
    void identicalPlaintextsWithDifferentSaltsProduceDifferentBlindIndexes(
            @ForAll("plaintext") String plaintext,
            @ForAll("distinctSaltPair") SaltPair saltPair) {

        BlindIndexService service = buildBlindIndexService();

        Result<BlindIndex, EncryptionError> indexWithFirstSalt =
                service.generateBlindIndex(plaintext, saltPair.first());
        Result<BlindIndex, EncryptionError> indexWithSecondSalt =
                service.generateBlindIndex(plaintext, saltPair.second());

        assertThat(indexWithFirstSalt.isSuccess())
                .as("Blind index generation with first salt should succeed for plaintext='%s'", plaintext)
                .isTrue();
        assertThat(indexWithSecondSalt.isSuccess())
                .as("Blind index generation with second salt should succeed for plaintext='%s'", plaintext)
                .isTrue();

        assertThat(indexWithFirstSalt.getValue().orElseThrow().getValue())
                .as("Blind index for plaintext='%s' with salt='%s' must differ from blind index "
                        + "with salt='%s' — per-record salt must prevent pattern matching correlation",
                        plaintext, saltPair.first(), saltPair.second())
                .isNotEqualTo(indexWithSecondSalt.getValue().orElseThrow().getValue());
    }

    /**
     * Property 16 (global salt variant): Two BlindIndexService instances configured
     * with different global salts must produce different blind indexes for the same
     * plaintext and per-record salt. This validates that the global salt contributes
     * to frequency analysis resistance.
     */
    @Property(tries = 200)
    @Label("Property 16 (global salt): Different global salts produce different blind indexes for identical inputs")
    void differentGlobalSaltsProduceDifferentBlindIndexes(
            @ForAll("plaintext") String plaintext,
            @ForAll("recordSalt") String recordSalt) {

        BlindIndexService serviceWithGlobalSalt1 =
                new BlindIndexService(new FixedBlindIndexKeyManager(), "global-salt-alpha-001");
        BlindIndexService serviceWithGlobalSalt2 =
                new BlindIndexService(new FixedBlindIndexKeyManager(), "global-salt-beta-002");

        Result<BlindIndex, EncryptionError> indexFromService1 =
                serviceWithGlobalSalt1.generateBlindIndex(plaintext, recordSalt);
        Result<BlindIndex, EncryptionError> indexFromService2 =
                serviceWithGlobalSalt2.generateBlindIndex(plaintext, recordSalt);

        assertThat(indexFromService1.isSuccess()).isTrue();
        assertThat(indexFromService2.isSuccess()).isTrue();

        assertThat(indexFromService1.getValue().orElseThrow().getValue())
                .as("Blind index for plaintext='%s' with global-salt-alpha must differ from "
                        + "blind index with global-salt-beta — global salt must resist frequency analysis",
                        plaintext)
                .isNotEqualTo(indexFromService2.getValue().orElseThrow().getValue());
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    /**
     * Generates PII-like plaintext values: emails, names, and general strings.
     */
    @Provide
    Arbitrary<String> plaintext() {
        Arbitrary<String> emails = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(10),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(5)
        ).as((user, domain, tld) ->
                user.toLowerCase() + "@" + domain.toLowerCase() + "." + tld.toLowerCase());

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
     * Generates a pair of distinct per-record salts. The two salts are guaranteed
     * to differ so that the property test exercises the salt-uniqueness guarantee.
     */
    @Provide
    Arbitrary<SaltPair> distinctSaltPair() {
        Arbitrary<String> saltArbitrary = Arbitraries.strings()
                .withCharRange('a', 'z')
                .ofMinLength(8)
                .ofMaxLength(32);

        return saltArbitrary.flatMap(first ->
                saltArbitrary
                        .filter(second -> !second.equals(first))
                        .map(second -> new SaltPair(first, second))
        );
    }

    /**
     * Generates a single per-record salt (used in the global-salt variant).
     */
    @Provide
    Arbitrary<String> recordSalt() {
        return Arbitraries.strings()
                .withCharRange('a', 'z')
                .ofMinLength(8)
                .ofMaxLength(32);
    }

    // -------------------------------------------------------------------------
    // Value type for a pair of distinct salts
    // -------------------------------------------------------------------------

    /**
     * Holds two distinct per-record salt values for use in property tests.
     */
    record SaltPair(String first, String second) {}

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    /**
     * Builds a self-contained BlindIndexService with a fixed blind index key
     * and the shared global salt.
     */
    private BlindIndexService buildBlindIndexService() {
        return new BlindIndexService(new FixedBlindIndexKeyManager(), GLOBAL_SALT);
    }

    /**
     * Minimal IKeyManager stub that returns a fixed 256-bit blind index key.
     * The key is shared across all instances so that only the salt varies.
     */
    private static final class FixedBlindIndexKeyManager implements IKeyManager {

        private static final byte[] FIXED_BLIND_INDEX_KEY;

        static {
            FIXED_BLIND_INDEX_KEY = new byte[32];
            new SecureRandom().nextBytes(FIXED_BLIND_INDEX_KEY);
        }

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            byte[] copy = new byte[FIXED_BLIND_INDEX_KEY.length];
            System.arraycopy(FIXED_BLIND_INDEX_KEY, 0, copy, 0, copy.length);
            return Result.success(copy);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in salt uniqueness test"));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in salt uniqueness test"));
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in salt uniqueness test"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in salt uniqueness test"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in salt uniqueness test"));
        }
    }
}
