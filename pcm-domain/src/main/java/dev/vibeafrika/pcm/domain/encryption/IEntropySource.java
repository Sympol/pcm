package dev.vibeafrika.pcm.domain.encryption;

/**
 * Domain interface for cryptographically secure entropy source.
 *
 * <p>Abstracts the underlying CSPRNG so the domain layer remains
 * framework-agnostic. Implementations must use operating-system-provided
 * secure random number generation.
 *
 * <p>Custom PRNG implementations are explicitly prohibited; only OS-backed
 * sources (e.g. {@code /dev/urandom}, hardware RNG) are permitted.
 */
public interface IEntropySource {

    /**
     * Returns a byte array of the requested length filled with cryptographically
     * secure random bytes.
     *
     * @param length the number of random bytes to generate; must be positive
     * @return a new byte array of {@code length} random bytes
     * @throws IllegalArgumentException if {@code length} is not positive
     * @throws EntropySourceException   if the entropy source is unavailable or fails
     */
    byte[] nextBytes(int length);

    /**
     * Unchecked exception thrown when the entropy source cannot produce random bytes.
     *
     * <p>Callers that catch this exception should treat it as a fatal error and
     * prevent further cryptographic operations.
     */
    final class EntropySourceException extends RuntimeException {

        public EntropySourceException(String message) {
            super(message);
        }

        public EntropySourceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
