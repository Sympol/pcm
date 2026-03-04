package dev.vibeafrika.pcm.domain.encryption;

import java.util.Arrays;
import java.util.Objects;

/**
 * Value object representing encrypted data in the standard ciphertext format.
 * Format: [version|algorithm_id|key_id|IV|ciphertext|authentication_tag]
 */
public final class Ciphertext {
    private final byte[] value;

    private Ciphertext(byte[] value) {
        this.value = Arrays.copyOf(value, value.length);
    }

    public static Ciphertext of(byte[] value) {
        Objects.requireNonNull(value, "Ciphertext value cannot be null");
        if (value.length < 46) { // Minimum: 1+1+16+12+0+16
            throw new IllegalArgumentException("Invalid ciphertext: too short");
        }
        return new Ciphertext(value);
    }

    public byte[] getValue() {
        return Arrays.copyOf(value, value.length);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Ciphertext that = (Ciphertext) o;
        return Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "Ciphertext{length=" + value.length + "}";
    }
}
