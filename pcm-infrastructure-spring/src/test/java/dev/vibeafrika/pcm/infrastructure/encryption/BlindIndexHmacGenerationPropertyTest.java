package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based test for blind index HMAC-SHA256 generation.
 *
 * <p><b>Property 15: Blind Index HMAC-SHA256 Generation</b>
 *
 * <p><b>Validates: </b>
 *
 * <p>For any plaintext and per-record salt, the blind index returned by
 * {@link BlindIndexService} must equal the value independently computed as:
 * <pre>
 *   HMAC-SHA256(blindIndexKey, globalSalt || recordSalt || normalize(plaintext))
 * </pre>
 * where {@code normalize(x) = x.trim().toLowerCase()}.
 */
class BlindIndexHmacGenerationPropertyTest {

    private static final String GLOBAL_SALT = "test-global-salt-hmac-property";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * Fixed blind index key shared across all test cases in this run.
     * Using a static key ensures the independently computed HMAC uses the same
     * key as the BlindIndexService under test.
     */
    private static final byte[] FIXED_BLIND_INDEX_KEY;

    static {
        FIXED_BLIND_INDEX_KEY = new byte[32];
        new SecureRandom().nextBytes(FIXED_BLIND_INDEX_KEY);
    }

    // -------------------------------------------------------------------------
    // Property 15: Blind Index HMAC-SHA256 Generation
    // -------------------------------------------------------------------------

    /**
     * Property 15: For any plaintext and record salt, the blind index produced by
     * {@code BlindIndexService.generateBlindIndex} must equal the value independently
     * computed as HMAC-SHA256(blindIndexKey, globalSalt || recordSalt || normalize(plaintext)).
     *
     * <p>This verifies that the service uses HMAC-SHA256 as the underlying primitive
     * and constructs the message in the correct order.
     */
    @Property(tries = 300)
    @Label("Property 15: Blind index equals independently computed HMAC-SHA256")
    void blindIndexEqualsIndependentlyComputedHmacSha256(
            @ForAll("plaintext") String plaintext,
            @ForAll("recordSalt") String recordSalt) throws Exception {

        BlindIndexService service = buildBlindIndexService();

        // Compute blind index via the service under test
        Result<BlindIndex, EncryptionError> result = service.generateBlindIndex(plaintext, recordSalt);

        assertThat(result.isSuccess())
                .as("Blind index generation for plaintext='%s', recordSalt='%s' should succeed",
                        plaintext, recordSalt)
                .isTrue();

        String serviceBlindIndex = result.getValue().orElseThrow().getValue();

        // Independently compute HMAC-SHA256 using the same key and salts
        String expectedBlindIndex = computeExpectedHmac(plaintext, recordSalt);

        assertThat(serviceBlindIndex)
                .as("Blind index for plaintext='%s' must equal independently computed "
                        + "HMAC-SHA256(key, globalSalt || recordSalt || normalize(plaintext))",
                        plaintext)
                .isEqualTo(expectedBlindIndex);
    }

    /**
     * Property 15 (normalization variant): The HMAC message uses the normalized
     * (lowercase + trimmed) form of the plaintext, not the raw input.
     *
     * <p>Verifies that the service normalizes before hashing by checking that the
     * blind index for an uppercase input matches the HMAC computed over the
     * lowercase-trimmed form.
     */
    @Property(tries = 200)
    @Label("Property 15 (normalization): HMAC is computed over normalized plaintext")
    void hmacIsComputedOverNormalizedPlaintext(
            @ForAll("plaintext") String plaintext,
            @ForAll("recordSalt") String recordSalt) throws Exception {

        BlindIndexService service = buildBlindIndexService();

        // Use uppercase variant as input — normalization should produce the same HMAC
        String upperCasePlaintext = plaintext.toUpperCase();

        Result<BlindIndex, EncryptionError> result = service.generateBlindIndex(upperCasePlaintext, recordSalt);

        assertThat(result.isSuccess())
                .as("Blind index generation for uppercase plaintext should succeed")
                .isTrue();

        String serviceBlindIndex = result.getValue().orElseThrow().getValue();

        // The expected HMAC is computed over the normalized (lowercase+trim) form
        String expectedBlindIndex = computeExpectedHmac(plaintext, recordSalt);

        assertThat(serviceBlindIndex)
                .as("Blind index for uppercase input must equal HMAC computed over normalized "
                        + "(lowercase+trim) plaintext — normalization must happen before hashing")
                .isEqualTo(expectedBlindIndex);
    }

    // -------------------------------------------------------------------------
    // Helper: independent HMAC-SHA256 computation
    // -------------------------------------------------------------------------

    /**
     * Independently computes the expected blind index as:
     * hex(HMAC-SHA256(key, globalSalt || recordSalt || normalize(plaintext)))
     *
     * <p>This mirrors the algorithm documented in {@link BlindIndexService}.
     */
    private String computeExpectedHmac(String plaintext, String recordSalt) throws Exception {
        String normalized = plaintext.trim().toLowerCase();
        String message = GLOBAL_SALT + recordSalt + normalized;
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(FIXED_BLIND_INDEX_KEY, HMAC_ALGORITHM));
        byte[] hmacBytes = mac.doFinal(messageBytes);

        return HexFormat.of().formatHex(hmacBytes);
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
     * Builds a BlindIndexService wired with the fixed blind index key so that
     * the independently computed HMAC uses the same key material.
     */
    private BlindIndexService buildBlindIndexService() {
        return new BlindIndexService(new FixedBlindIndexKeyManager(), GLOBAL_SALT);
    }

    /**
     * Minimal IKeyManager stub that returns the shared fixed blind index key.
     */
    private static final class FixedBlindIndexKeyManager implements IKeyManager {

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            // Return a copy to prevent mutation of the shared key
            byte[] copy = new byte[FIXED_BLIND_INDEX_KEY.length];
            System.arraycopy(FIXED_BLIND_INDEX_KEY, 0, copy, 0, copy.length);
            return Result.success(copy);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index HMAC test"));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index HMAC test"));
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index HMAC test"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index HMAC test"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in blind index HMAC test"));
        }
    }
}
