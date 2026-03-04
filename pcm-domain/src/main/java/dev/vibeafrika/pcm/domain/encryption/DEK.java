package dev.vibeafrika.pcm.domain.encryption;

import java.util.Arrays;
import java.util.Objects;

/**
 * Value object representing a Data Encryption Key (DEK).
 * DEKs are used to encrypt actual PII data and are themselves encrypted by KEKs.
 */
public final class DEK {
    private final byte[] keyMaterial;

    private DEK(byte[] keyMaterial) {
        this.keyMaterial = Arrays.copyOf(keyMaterial, keyMaterial.length);
    }

    public static DEK of(byte[] keyMaterial) {
        Objects.requireNonNull(keyMaterial, "DEK key material cannot be null");
        if (keyMaterial.length != 32) { // 256 bits
            throw new IllegalArgumentException("DEK must be exactly 256 bits (32 bytes)");
        }
        return new DEK(keyMaterial);
    }

    public byte[] getKeyMaterial() {
        return Arrays.copyOf(keyMaterial, keyMaterial.length);
    }

    /**
     * Securely wipes the key material from memory.
     */
    public void wipe() {
        Arrays.fill(keyMaterial, (byte) 0);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DEK dek = (DEK) o;
        return Arrays.equals(keyMaterial, dek.keyMaterial);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyMaterial);
    }

    @Override
    public String toString() {
        return "DEK{length=" + keyMaterial.length + "}";
    }
}
