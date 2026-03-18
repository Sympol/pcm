package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.Ciphertext;
import dev.vibeafrika.pcm.domain.encryption.DecryptionError;
import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;
import dev.vibeafrika.pcm.domain.encryption.Result;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CiphertextFormat.
 * 
 * Tests basic formatting and parsing functionality, edge cases, and error handling.
 */
class CiphertextFormatTest {

    @Test
    void testFormatAndParse_AES256GCM_Success() {
        // Arrange
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        UUID keyId = UUID.randomUUID();
        byte[] iv = new byte[12];
        byte[] ciphertext = "encrypted data".getBytes();
        byte[] authTag = new byte[16];

        // Fill with test data
        for (int i = 0; i < iv.length; i++) iv[i] = (byte) i;
        for (int i = 0; i < authTag.length; i++) authTag[i] = (byte) (i + 100);

        // Act - Format
        Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );

        // Assert - Format succeeded
        assertTrue(formatResult.isSuccess());
        Ciphertext formatted = formatResult.getValue().get();
        assertNotNull(formatted);

        // Act - Parse
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = 
            CiphertextFormat.parse(formatted);

        // Assert - Parse succeeded
        assertTrue(parseResult.isSuccess());
        CiphertextFormat.ParsedCiphertext parsed = parseResult.getValue().get();

        // Assert - All fields match
        assertEquals(version, parsed.getVersion());
        assertEquals(EncryptionAlgorithm.AES_256_GCM, parsed.getAlgorithm());
        assertEquals(keyId, parsed.getKeyId());
        assertArrayEquals(iv, parsed.getIv());
        assertArrayEquals(ciphertext, parsed.getCiphertext());
        assertArrayEquals(authTag, parsed.getAuthTag());
    }

    @Test
    void testFormatAndParse_AES256CBC_Success() {
        // Arrange
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_CBC_HMAC;
        UUID keyId = UUID.randomUUID();
        byte[] iv = new byte[12];
        byte[] ciphertext = "test data".getBytes();
        byte[] authTag = new byte[16];

        // Act - Format
        Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );

        // Assert - Format succeeded
        assertTrue(formatResult.isSuccess());

        // Act - Parse
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = 
            CiphertextFormat.parse(formatResult.getValue().get());

        // Assert - Parse succeeded and algorithm is correct
        assertTrue(parseResult.isSuccess());
        assertEquals(EncryptionAlgorithm.AES_256_CBC_HMAC, parseResult.getValue().get().getAlgorithm());
    }

    @Test
    void testFormat_NullKeyId_Failure() {
        // Arrange
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        byte[] iv = new byte[12];
        byte[] ciphertext = "data".getBytes();
        byte[] authTag = new byte[16];

        // Act
        Result<Ciphertext, DecryptionError> result = CiphertextFormat.format(
            version, algorithmId, null, iv, ciphertext, authTag
        );

        // Assert
        assertTrue(result.isFailure());
        assertEquals("INVALID_FORMAT", result.getError().get().getCode());
    }

    @Test
    void testFormat_InvalidIVLength_Failure() {
        // Arrange
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        UUID keyId = UUID.randomUUID();
        byte[] iv = new byte[10]; // Wrong length
        byte[] ciphertext = "data".getBytes();
        byte[] authTag = new byte[16];

        // Act
        Result<Ciphertext, DecryptionError> result = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );

        // Assert
        assertTrue(result.isFailure());
        assertEquals("INVALID_FORMAT", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("IV must be exactly 12 bytes"));
    }

    @Test
    void testFormat_InvalidAuthTagLength_Failure() {
        // Arrange
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        UUID keyId = UUID.randomUUID();
        byte[] iv = new byte[12];
        byte[] ciphertext = "data".getBytes();
        byte[] authTag = new byte[10]; // Wrong length

        // Act
        Result<Ciphertext, DecryptionError> result = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );

        // Assert
        assertTrue(result.isFailure());
        assertEquals("INVALID_FORMAT", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("Authentication tag must be exactly 16 bytes"));
    }

    @Test
    void testParse_TooShort_Failure() {
        // Arrange
        byte[] tooShort = new byte[40]; // Less than minimum 46 bytes

        // Act
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result = 
            CiphertextFormat.parse(tooShort);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("Ciphertext too short"));
    }

    @Test
    void testParse_UnsupportedVersion_Failure() {
        // Arrange - Create a ciphertext with unsupported version
        byte[] bytes = new byte[46];
        bytes[0] = 0x02; // Unsupported version
        bytes[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;

        // Act
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result = 
            CiphertextFormat.parse(bytes);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("UNSUPPORTED_VERSION", result.getError().get().getCode());
    }

    @Test
    void testParse_UnsupportedAlgorithm_Failure() {
        // Arrange - Create a ciphertext with unsupported algorithm
        byte[] bytes = new byte[46];
        bytes[0] = CiphertextFormat.VERSION_1;
        bytes[1] = 0x03; // Unsupported algorithm

        // Act
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result = 
            CiphertextFormat.parse(bytes);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("UNSUPPORTED_ALGORITHM", result.getError().get().getCode());
    }

    @Test
    void testUUIDBigEndianSerialization() {
        // Arrange - Use a specific UUID to verify big-endian format
        UUID keyId = new UUID(0x123456789ABCDEF0L, 0xFEDCBA9876543210L);
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        byte[] iv = new byte[12];
        byte[] ciphertext = "test".getBytes();
        byte[] authTag = new byte[16];

        // Act
        Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );
        assertTrue(formatResult.isSuccess());

        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = 
            CiphertextFormat.parse(formatResult.getValue().get());
        assertTrue(parseResult.isSuccess());

        // Assert - UUID should be preserved exactly
        assertEquals(keyId, parseResult.getValue().get().getKeyId());
    }

    @Test
    void testEmptyCiphertext_Success() {
        // Arrange - Empty ciphertext is valid (e.g., encrypting empty string)
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        UUID keyId = UUID.randomUUID();
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[0]; // Empty
        byte[] authTag = new byte[16];

        // Act
        Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );

        // Assert
        assertTrue(formatResult.isSuccess());

        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = 
            CiphertextFormat.parse(formatResult.getValue().get());
        assertTrue(parseResult.isSuccess());
        assertEquals(0, parseResult.getValue().get().getCiphertext().length);
    }

    @Test
    void testAlgorithmToId_AllAlgorithms() {
        // Test all supported algorithms
        assertEquals(CiphertextFormat.ALGORITHM_AES_256_GCM, 
            CiphertextFormat.algorithmToId(EncryptionAlgorithm.AES_256_GCM));
        assertEquals(CiphertextFormat.ALGORITHM_AES_256_CBC_HMAC, 
            CiphertextFormat.algorithmToId(EncryptionAlgorithm.AES_256_CBC_HMAC));
    }

    @Test
    void testAlgorithmToId_Null_ThrowsException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            CiphertextFormat.algorithmToId(null);
        });
    }

    /**
     * Test parsing with multiple invalid version bytes.
     */
    @Test
    void testParse_InvalidVersionBytes_Failure() {
        // Test version 0x00
        byte[] bytes1 = new byte[46];
        bytes1[0] = 0x00;
        bytes1[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result1 = 
            CiphertextFormat.parse(bytes1);
        assertTrue(result1.isFailure());
        assertEquals("UNSUPPORTED_VERSION", result1.getError().get().getCode());

        // Test version 0x02
        byte[] bytes2 = new byte[46];
        bytes2[0] = 0x02;
        bytes2[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result2 = 
            CiphertextFormat.parse(bytes2);
        assertTrue(result2.isFailure());
        assertEquals("UNSUPPORTED_VERSION", result2.getError().get().getCode());

        // Test version 0xFF
        byte[] bytes3 = new byte[46];
        bytes3[0] = (byte) 0xFF;
        bytes3[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result3 = 
            CiphertextFormat.parse(bytes3);
        assertTrue(result3.isFailure());
        assertEquals("UNSUPPORTED_VERSION", result3.getError().get().getCode());
    }

    /**
     * Test parsing with multiple unsupported algorithm IDs.
     */
    @Test
    void testParse_UnsupportedAlgorithmIDs_Failure() {
        // Test algorithm 0x00
        byte[] bytes1 = new byte[46];
        bytes1[0] = CiphertextFormat.VERSION_1;
        bytes1[1] = 0x00;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result1 = 
            CiphertextFormat.parse(bytes1);
        assertTrue(result1.isFailure());
        assertEquals("UNSUPPORTED_ALGORITHM", result1.getError().get().getCode());

        // Test algorithm 0x03
        byte[] bytes2 = new byte[46];
        bytes2[0] = CiphertextFormat.VERSION_1;
        bytes2[1] = 0x03;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result2 = 
            CiphertextFormat.parse(bytes2);
        assertTrue(result2.isFailure());
        assertEquals("UNSUPPORTED_ALGORITHM", result2.getError().get().getCode());

        // Test algorithm 0xFF
        byte[] bytes3 = new byte[46];
        bytes3[0] = CiphertextFormat.VERSION_1;
        bytes3[1] = (byte) 0xFF;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result3 = 
            CiphertextFormat.parse(bytes3);
        assertTrue(result3.isFailure());
        assertEquals("UNSUPPORTED_ALGORITHM", result3.getError().get().getCode());
    }

    /**
     * Test parsing truncated ciphertext at various positions.
     */
    @Test
    void testParse_TruncatedAtDifferentPositions_Failure() {
        // Truncated after version byte (1 byte)
        byte[] bytes1 = new byte[1];
        bytes1[0] = CiphertextFormat.VERSION_1;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result1 = 
            CiphertextFormat.parse(bytes1);
        assertTrue(result1.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result1.getError().get().getCode());
        assertTrue(result1.getError().get().getMessage().contains("too short"));

        // Truncated after algorithm byte (2 bytes)
        byte[] bytes2 = new byte[2];
        bytes2[0] = CiphertextFormat.VERSION_1;
        bytes2[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result2 = 
            CiphertextFormat.parse(bytes2);
        assertTrue(result2.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result2.getError().get().getCode());

        // Truncated in middle of key ID (10 bytes)
        byte[] bytes3 = new byte[10];
        bytes3[0] = CiphertextFormat.VERSION_1;
        bytes3[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result3 = 
            CiphertextFormat.parse(bytes3);
        assertTrue(result3.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result3.getError().get().getCode());

        // Truncated after key ID (18 bytes)
        byte[] bytes4 = new byte[18];
        bytes4[0] = CiphertextFormat.VERSION_1;
        bytes4[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result4 = 
            CiphertextFormat.parse(bytes4);
        assertTrue(result4.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result4.getError().get().getCode());

        // Truncated in middle of IV (25 bytes)
        byte[] bytes5 = new byte[25];
        bytes5[0] = CiphertextFormat.VERSION_1;
        bytes5[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result5 = 
            CiphertextFormat.parse(bytes5);
        assertTrue(result5.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result5.getError().get().getCode());

        // Exactly at minimum size boundary minus 1 (45 bytes - missing 1 byte of auth tag)
        byte[] bytes6 = new byte[45];
        bytes6[0] = CiphertextFormat.VERSION_1;
        bytes6[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result6 = 
            CiphertextFormat.parse(bytes6);
        assertTrue(result6.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result6.getError().get().getCode());
    }

    /**
     * Test parsing ciphertext missing authentication tag.
     */
    @Test
    void testParse_MissingAuthTag_Failure() {
        // Create a ciphertext with header + some data but no auth tag
        // Minimum is 46 bytes (30 header + 0 ciphertext + 16 auth tag)
        // So 30 bytes would be just the header with no ciphertext or auth tag
        byte[] bytes = new byte[30];
        bytes[0] = CiphertextFormat.VERSION_1;
        bytes[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;

        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result = 
            CiphertextFormat.parse(bytes);

        assertTrue(result.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("too short"));
    }

    /**
     * Test UUID big-endian serialization with edge case UUIDs.
     */
    @Test
    void testUUIDBigEndianSerialization_EdgeCases() {
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        byte[] iv = new byte[12];
        byte[] ciphertext = "test".getBytes();
        byte[] authTag = new byte[16];

        // Test UUID with all zeros
        UUID zeroUuid = new UUID(0L, 0L);
        Result<Ciphertext, DecryptionError> formatResult1 = CiphertextFormat.format(
            version, algorithmId, zeroUuid, iv, ciphertext, authTag
        );
        assertTrue(formatResult1.isSuccess());
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult1 = 
            CiphertextFormat.parse(formatResult1.getValue().get());
        assertTrue(parseResult1.isSuccess());
        assertEquals(zeroUuid, parseResult1.getValue().get().getKeyId());

        // Test UUID with all ones (0xFFFFFFFFFFFFFFFF)
        UUID onesUuid = new UUID(-1L, -1L);
        Result<Ciphertext, DecryptionError> formatResult2 = CiphertextFormat.format(
            version, algorithmId, onesUuid, iv, ciphertext, authTag
        );
        assertTrue(formatResult2.isSuccess());
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult2 = 
            CiphertextFormat.parse(formatResult2.getValue().get());
        assertTrue(parseResult2.isSuccess());
        assertEquals(onesUuid, parseResult2.getValue().get().getKeyId());

        // Test UUID with specific bit patterns to verify byte order
        // Most significant bits: 0xAAAAAAAAAAAAAAAA
        // Least significant bits: 0x5555555555555555
        UUID patternUuid = new UUID(0xAAAAAAAAAAAAAAAAL, 0x5555555555555555L);
        Result<Ciphertext, DecryptionError> formatResult3 = CiphertextFormat.format(
            version, algorithmId, patternUuid, iv, ciphertext, authTag
        );
        assertTrue(formatResult3.isSuccess());
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult3 = 
            CiphertextFormat.parse(formatResult3.getValue().get());
        assertTrue(parseResult3.isSuccess());
        assertEquals(patternUuid, parseResult3.getValue().get().getKeyId());

        // Test UUID with alternating bytes to verify endianness
        UUID alternatingUuid = new UUID(0x0123456789ABCDEFL, 0xFEDCBA9876543210L);
        Result<Ciphertext, DecryptionError> formatResult4 = CiphertextFormat.format(
            version, algorithmId, alternatingUuid, iv, ciphertext, authTag
        );
        assertTrue(formatResult4.isSuccess());
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult4 = 
            CiphertextFormat.parse(formatResult4.getValue().get());
        assertTrue(parseResult4.isSuccess());
        assertEquals(alternatingUuid, parseResult4.getValue().get().getKeyId());
    }

    /**
     * Test parsing exactly at minimum size boundary (46 bytes).
     */
    @Test
    void testParse_ExactlyMinimumSize_Success() {
        // Create a valid ciphertext with exactly 46 bytes (minimum size)
        // This means 0 bytes of actual ciphertext data
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        UUID keyId = UUID.randomUUID();
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[0]; // Empty ciphertext
        byte[] authTag = new byte[16];

        // Fill with test data
        for (int i = 0; i < iv.length; i++) iv[i] = (byte) i;
        for (int i = 0; i < authTag.length; i++) authTag[i] = (byte) (i + 100);

        Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );
        assertTrue(formatResult.isSuccess());

        byte[] bytes = formatResult.getValue().get().getValue();
        assertEquals(46, bytes.length, "Minimum ciphertext should be exactly 46 bytes");

        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = 
            CiphertextFormat.parse(bytes);
        assertTrue(parseResult.isSuccess());
        assertEquals(0, parseResult.getValue().get().getCiphertext().length);
    }

    /**
     * Test parsing null ciphertext bytes.
     */
    @Test
    void testParse_NullBytes_Failure() {
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result = 
            CiphertextFormat.parse((byte[]) null);

        assertTrue(result.isFailure());
        assertEquals("INVALID_CIPHERTEXT_FORMAT", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("cannot be null"));
    }

    /**
     * Test parsing with large ciphertext to ensure no size limitations.
     */
    @Test
    void testParse_LargeCiphertext_Success() {
        // Create a ciphertext with 10KB of data
        byte version = CiphertextFormat.VERSION_1;
        byte algorithmId = CiphertextFormat.ALGORITHM_AES_256_GCM;
        UUID keyId = UUID.randomUUID();
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[10240]; // 10KB
        byte[] authTag = new byte[16];

        // Fill with test data
        for (int i = 0; i < ciphertext.length; i++) {
            ciphertext[i] = (byte) (i % 256);
        }

        Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
            version, algorithmId, keyId, iv, ciphertext, authTag
        );
        assertTrue(formatResult.isSuccess());

        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = 
            CiphertextFormat.parse(formatResult.getValue().get());
        assertTrue(parseResult.isSuccess());
        assertEquals(10240, parseResult.getValue().get().getCiphertext().length);
        assertArrayEquals(ciphertext, parseResult.getValue().get().getCiphertext());
    }
}
