package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.ConstantTime;
import dev.vibeafrika.pcm.domain.encryption.DEK;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for constant-time operations.
 *
 * <p>These tests verify correctness of the constant-time comparisons.
 * True timing-attack resistance cannot be proven by unit tests alone —
 * it requires hardware-level analysis. The tests here confirm that the
 * methods return the right boolean result under all input combinations.
 */
@DisplayName("Constant-Time Operations")
class ConstantTimeOperationsTest {

    // -----------------------------------------------------------------------
    // ConstantTime.verifyAuthTag
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Authentication tag verification")
    class AuthTagVerification {

        @Test
        @DisplayName("identical tags return true")
        void identicalTagsReturnTrue() {
            byte[] tag = new byte[16];
            new SecureRandom().nextBytes(tag);
            byte[] copy = tag.clone();

            assertThat(ConstantTime.verifyAuthTag(tag, copy)).isTrue();
        }

        @Test
        @DisplayName("tags differing in first byte return false")
        void tagsDifferingInFirstByteReturnFalse() {
            byte[] expected = new byte[16];
            new SecureRandom().nextBytes(expected);
            byte[] actual = expected.clone();
            actual[0] ^= 0xFF; // flip first byte

            assertThat(ConstantTime.verifyAuthTag(expected, actual)).isFalse();
        }

        @Test
        @DisplayName("tags differing in last byte return false")
        void tagsDifferingInLastByteReturnFalse() {
            byte[] expected = new byte[16];
            new SecureRandom().nextBytes(expected);
            byte[] actual = expected.clone();
            actual[15] ^= 0xFF; // flip last byte

            assertThat(ConstantTime.verifyAuthTag(expected, actual)).isFalse();
        }

        @Test
        @DisplayName("tags of different lengths return false")
        void tagsOfDifferentLengthsReturnFalse() {
            byte[] expected = new byte[16];
            byte[] actual = new byte[15];
            new SecureRandom().nextBytes(expected);
            System.arraycopy(expected, 0, actual, 0, 15);

            assertThat(ConstantTime.verifyAuthTag(expected, actual)).isFalse();
        }

        @Test
        @DisplayName("all-zero tags are equal")
        void allZeroTagsAreEqual() {
            byte[] a = new byte[16];
            byte[] b = new byte[16];

            assertThat(ConstantTime.verifyAuthTag(a, b)).isTrue();
        }
    }

    // -----------------------------------------------------------------------
    // ConstantTime.verifyHmac 
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("HMAC verification")
    class HmacVerification {

        private byte[] computeHmac(byte[] key, byte[] message) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        }

        @Test
        @DisplayName("same key and message produce matching HMACs")
        void sameKeyAndMessageProduceMatchingHmacs() throws Exception {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            byte[] message = "test-plaintext".getBytes(StandardCharsets.UTF_8);

            byte[] hmac1 = computeHmac(key, message);
            byte[] hmac2 = computeHmac(key, message);

            assertThat(ConstantTime.verifyHmac(hmac1, hmac2)).isTrue();
        }

        @Test
        @DisplayName("different messages produce non-matching HMACs")
        void differentMessagesProduceNonMatchingHmacs() throws Exception {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);

            byte[] hmac1 = computeHmac(key, "message-a".getBytes(StandardCharsets.UTF_8));
            byte[] hmac2 = computeHmac(key, "message-b".getBytes(StandardCharsets.UTF_8));

            assertThat(ConstantTime.verifyHmac(hmac1, hmac2)).isFalse();
        }

        @Test
        @DisplayName("different keys produce non-matching HMACs")
        void differentKeysProduceNonMatchingHmacs() throws Exception {
            byte[] key1 = new byte[32];
            byte[] key2 = new byte[32];
            new SecureRandom().nextBytes(key1);
            new SecureRandom().nextBytes(key2);
            byte[] message = "same-message".getBytes(StandardCharsets.UTF_8);

            byte[] hmac1 = computeHmac(key1, message);
            byte[] hmac2 = computeHmac(key2, message);

            assertThat(ConstantTime.verifyHmac(hmac1, hmac2)).isFalse();
        }

        @Test
        @DisplayName("single-byte difference in HMAC returns false")
        void singleByteDifferenceReturnsFalse() throws Exception {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            byte[] message = "data".getBytes(StandardCharsets.UTF_8);

            byte[] expected = computeHmac(key, message);
            byte[] tampered = expected.clone();
            tampered[0] ^= 0x01;

            assertThat(ConstantTime.verifyHmac(expected, tampered)).isFalse();
        }
    }

    // -----------------------------------------------------------------------
    // DEK key equality 
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("DEK key equality")
    class DekKeyEquality {

        @Test
        @DisplayName("DEKs with identical key material are equal")
        void deksWithIdenticalMaterialAreEqual() {
            byte[] material = new byte[32];
            new SecureRandom().nextBytes(material);

            DEK dek1 = DEK.of(material);
            DEK dek2 = DEK.of(material);

            assertThat(dek1).isEqualTo(dek2);
        }

        @Test
        @DisplayName("DEKs with different key material are not equal")
        void deksWithDifferentMaterialAreNotEqual() {
            byte[] material1 = new byte[32];
            byte[] material2 = new byte[32];
            new SecureRandom().nextBytes(material1);
            new SecureRandom().nextBytes(material2);

            DEK dek1 = DEK.of(material1);
            DEK dek2 = DEK.of(material2);

            assertThat(dek1).isNotEqualTo(dek2);
        }

        @Test
        @DisplayName("DEKs differing in only one byte are not equal")
        void deksWithSingleByteDifferenceAreNotEqual() {
            byte[] material = new byte[32];
            new SecureRandom().nextBytes(material);
            byte[] modified = material.clone();
            modified[0] ^= 0xFF;

            DEK dek1 = DEK.of(material);
            DEK dek2 = DEK.of(modified);

            assertThat(dek1).isNotEqualTo(dek2);
        }

        @Test
        @DisplayName("DEK is equal to itself (reflexive)")
        void dekIsEqualToItself() {
            byte[] material = new byte[32];
            new SecureRandom().nextBytes(material);
            DEK dek = DEK.of(material);

            assertThat(dek).isEqualTo(dek);
        }

        @Test
        @DisplayName("DEK is not equal to null")
        void dekIsNotEqualToNull() {
            byte[] material = new byte[32];
            new SecureRandom().nextBytes(material);
            DEK dek = DEK.of(material);

            assertThat(dek.equals(null)).isFalse();
        }
    }

    // -----------------------------------------------------------------------
    // ConstantTime.equals edge cases
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("ConstantTime.equals edge cases")
    class ConstantTimeEquals {

        @Test
        @DisplayName("empty arrays are equal")
        void emptyArraysAreEqual() {
            assertThat(ConstantTime.equals(new byte[0], new byte[0])).isTrue();
        }

        @Test
        @DisplayName("null arrays are equal to each other")
        void nullArraysAreEqualToEachOther() {
            assertThat(ConstantTime.equals(null, null)).isTrue();
        }

        @Test
        @DisplayName("null vs non-null returns false")
        void nullVsNonNullReturnsFalse() {
            assertThat(ConstantTime.equals(null, new byte[]{1})).isFalse();
            assertThat(ConstantTime.equals(new byte[]{1}, null)).isFalse();
        }

        @Test
        @DisplayName("single-element arrays with same value are equal")
        void singleElementSameValueAreEqual() {
            assertThat(ConstantTime.equals(new byte[]{42}, new byte[]{42})).isTrue();
        }

        @Test
        @DisplayName("single-element arrays with different values are not equal")
        void singleElementDifferentValuesAreNotEqual() {
            assertThat(ConstantTime.equals(new byte[]{1}, new byte[]{2})).isFalse();
        }
    }
}
