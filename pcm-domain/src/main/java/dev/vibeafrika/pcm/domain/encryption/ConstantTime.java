package dev.vibeafrika.pcm.domain.encryption;

import java.security.MessageDigest;

/**
 * Constant-time comparison utilities to prevent timing side-channel attacks.
 *
 * <p>Standard Java equality checks (Arrays.equals, String.equals) short-circuit
 * on the first differing byte, leaking information about secret values through
 * timing differences. These methods always examine every byte regardless of
 * where a mismatch occurs.
 */
public final class ConstantTime {

    private ConstantTime() {
        // utility class
    }

    /**
     * Compares two byte arrays in constant time.
     *
     * <p>Uses {@link MessageDigest#isEqual} which is guaranteed by the JDK to
     * run in constant time regardless of where the first difference occurs.
     * Both arrays are fully traversed even when they differ in length.
     *
     * @param a first byte array (must not be null)
     * @param b second byte array (must not be null)
     * @return {@code true} if the arrays have the same length and identical contents
     */
    public static boolean equals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            // Avoid short-circuit: evaluate both null checks before returning
            boolean aNull = (a == null);
            boolean bNull = (b == null);
            return aNull && bNull;
        }
        // MessageDigest.isEqual is constant-time and handles length differences
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Verifies an authentication tag in constant time.
     *
     * <p>Equivalent to {@link #equals(byte[], byte[])} but named for clarity
     * at call sites dealing with GCM authentication tags.
     *
     * @param expected the expected authentication tag
     * @param actual   the actual authentication tag to verify
     * @return {@code true} if the tags match
     */
    public static boolean verifyAuthTag(byte[] expected, byte[] actual) {
        return equals(expected, actual);
    }

    /**
     * Verifies an HMAC value in constant time.
     *
     * <p>Equivalent to {@link #equals(byte[], byte[])} but named for clarity
     * at call sites dealing with HMAC verification.
     *
     * @param expected the expected HMAC
     * @param actual   the actual HMAC to verify
     * @return {@code true} if the HMACs match
     */
    public static boolean verifyHmac(byte[] expected, byte[] actual) {
        return equals(expected, actual);
    }
}
