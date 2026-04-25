package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.IEntropySource;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * JVM implementation of {@link IEntropySource} backed by a validated {@link SecureRandom}.
 *
 * <p>The {@link SecureRandom} instance is provided by {@link EntropySourceValidator},
 * which selects the best available OS-backed algorithm at startup and validates it
 * before this class is instantiated.
 *
 * <p>This class is framework-agnostic and can be used anywhere an {@link IEntropySource}
 * is required without introducing Spring dependencies into the domain layer.
 */
public final class JvmEntropySource implements IEntropySource {

    private final SecureRandom secureRandom;

    /**
     * Creates a {@code JvmEntropySource} using the given validated {@link SecureRandom}.
     *
     * @param secureRandom the validated entropy source; must not be {@code null}
     */
    public JvmEntropySource(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom must not be null");
    }

    /**
     * {@inheritDoc}
     *
     * <p>Delegates to {@link SecureRandom#nextBytes(byte[])} using the OS-backed
     * instance validated at startup.
     *
     * @throws IllegalArgumentException if {@code length} is not positive
     * @throws EntropySourceException   if the underlying {@link SecureRandom} throws
     */
    @Override
    public byte[] nextBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive, got: " + length);
        }
        try {
            byte[] bytes = new byte[length];
            secureRandom.nextBytes(bytes);
            return bytes;
        } catch (Exception e) {
            throw new EntropySourceException(
                    "Failed to generate " + length + " random bytes from JVM entropy source", e);
        }
    }
}
