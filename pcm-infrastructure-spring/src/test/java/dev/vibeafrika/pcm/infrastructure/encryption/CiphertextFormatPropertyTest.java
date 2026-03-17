package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.Ciphertext;
import dev.vibeafrika.pcm.domain.encryption.Result;
import net.jqwik.api.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for CiphertextFormat.
 * 
 * These tests verify that the ciphertext format specification is correctly implemented
 * by generating arbitrary valid inputs and checking that the format method produces
 * ciphertexts that conform to the specification.
 */
class CiphertextFormatPropertyTest {

    /**
     * 
     * Property 44: Ciphertext Format Specification
     * 
     * For any valid encryption components (version, algorithm ID, key ID, IV, ciphertext, auth tag),
     * the formatted ciphertext must follow the exact specification:
     * - Byte 0: version (0x01)
     * - Byte 1: algorithm ID (0x01 or 0x02)
     * - Bytes 2-17: key ID (UUID, 16 bytes, big-endian)
     * - Bytes 18-29: IV (12 bytes)
     * - Bytes 30 to length-16: ciphertext (variable)
     * - Last 16 bytes: authentication tag
     */
    @Property
    void formattedCiphertextFollowsSpecification(
            @ForAll("validKeyId") UUID keyId,
            @ForAll("validAlgorithmId") byte algorithmId,
            @ForAll("validIV") byte[] iv,
            @ForAll("validCiphertext") byte[] ciphertext,
            @ForAll("validAuthTag") byte[] authTag) {

        // Format the ciphertext
        Result<Ciphertext, ?> result = CiphertextFormat.format(
                CiphertextFormat.VERSION_1,
                algorithmId,
                keyId,
                iv,
                ciphertext,
                authTag
        );

        // Verify formatting succeeded
        assertThat(result.isSuccess()).isTrue();
        byte[] formatted = result.getValue().orElseThrow().getValue();

        // Verify total length: 46 bytes overhead + ciphertext length
        int expectedLength = 1 + 1 + 16 + 12 + ciphertext.length + 16;
        assertThat(formatted).hasSize(expectedLength);

        // Verify byte 0: version
        assertThat(formatted[0]).isEqualTo(CiphertextFormat.VERSION_1);

        // Verify byte 1: algorithm ID
        assertThat(formatted[1]).isEqualTo(algorithmId);

        // Verify bytes 2-17: key ID (UUID in big-endian format)
        ByteBuffer keyIdBuffer = ByteBuffer.wrap(formatted, 2, 16);
        keyIdBuffer.order(ByteOrder.BIG_ENDIAN);
        long mostSigBits = keyIdBuffer.getLong();
        long leastSigBits = keyIdBuffer.getLong();
        UUID extractedKeyId = new UUID(mostSigBits, leastSigBits);
        assertThat(extractedKeyId).isEqualTo(keyId);

        // Verify bytes 18-29: IV
        byte[] extractedIV = new byte[12];
        System.arraycopy(formatted, 18, extractedIV, 0, 12);
        assertThat(extractedIV).isEqualTo(iv);

        // Verify bytes 30 to length-16: ciphertext
        byte[] extractedCiphertext = new byte[ciphertext.length];
        System.arraycopy(formatted, 30, extractedCiphertext, 0, ciphertext.length);
        assertThat(extractedCiphertext).isEqualTo(ciphertext);

        // Verify last 16 bytes: authentication tag
        byte[] extractedAuthTag = new byte[16];
        System.arraycopy(formatted, formatted.length - 16, extractedAuthTag, 0, 16);
        assertThat(extractedAuthTag).isEqualTo(authTag);
    }

    // Arbitraries (generators) for property-based testing

    @Provide
    Arbitrary<UUID> validKeyId() {
        return Arbitraries.randomValue(random -> UUID.randomUUID());
    }

    @Provide
    Arbitrary<Byte> validAlgorithmId() {
        return Arbitraries.of(
                CiphertextFormat.ALGORITHM_AES_256_GCM,
                CiphertextFormat.ALGORITHM_AES_256_CBC_HMAC
        );
    }

    @Provide
    Arbitrary<byte[]> validIV() {
        return Arbitraries.bytes()
                .array(byte[].class)
                .ofSize(12);
    }

    @Provide
    Arbitrary<byte[]> validCiphertext() {
        return Arbitraries.bytes()
                .array(byte[].class)
                .ofMinSize(0)
                .ofMaxSize(1000);
    }

    @Provide
    Arbitrary<byte[]> validAuthTag() {
        return Arbitraries.bytes()
                .array(byte[].class)
                .ofSize(16);
    }


    /**
     * **Validates: Requirements 26.2**
     *
     * Property 45: Ciphertext Version Byte
     *
     * For any valid set of ciphertext components (version, algorithmId, keyId, iv, ciphertext, authTag),
     * formatting them into bytes and then parsing those bytes should produce equivalent components.
     *
     * This property verifies the round-trip correctness of the format/parse operations:
     * format(components) -> parse(bytes) -> components'
     * where components' is equivalent to the original components.
     */
    @Property
    void formatThenParseProducesEquivalentComponents(
            @ForAll("validKeyId") UUID keyId,
            @ForAll("validAlgorithmId") byte algorithmId,
            @ForAll("validIV") byte[] iv,
            @ForAll("validCiphertext") byte[] ciphertext,
            @ForAll("validAuthTag") byte[] authTag) {

        // Format the components into ciphertext
        Result<Ciphertext, ?> formatResult = CiphertextFormat.format(
                CiphertextFormat.VERSION_1,
                algorithmId,
                keyId,
                iv,
                ciphertext,
                authTag
        );

        // Verify formatting succeeded
        assertThat(formatResult.isSuccess()).isTrue();
        Ciphertext formatted = formatResult.getValue().orElseThrow();

        // Parse the formatted ciphertext back into components
        Result<CiphertextFormat.ParsedCiphertext, ?> parseResult = CiphertextFormat.parse(formatted);

        // Verify parsing succeeded
        assertThat(parseResult.isSuccess()).isTrue();
        CiphertextFormat.ParsedCiphertext parsed = parseResult.getValue().orElseThrow();

        // Verify all components are equivalent
        assertThat(parsed.getVersion()).isEqualTo(CiphertextFormat.VERSION_1);
        assertThat(CiphertextFormat.algorithmToId(parsed.getAlgorithm())).isEqualTo(algorithmId);
        assertThat(parsed.getKeyId()).isEqualTo(keyId);
        assertThat(parsed.getIv()).isEqualTo(iv);
        assertThat(parsed.getCiphertext()).isEqualTo(ciphertext);
        assertThat(parsed.getAuthTag()).isEqualTo(authTag);
    }

}
