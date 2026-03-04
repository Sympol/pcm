package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Value object representing a blind index for searchable encryption.
 * Blind indexes enable exact-match searching on encrypted fields while
 * resisting frequency analysis and pattern matching attacks.
 */
public final class BlindIndex {
    private final String value;
    private final String algorithm;
    private final int version;

    private BlindIndex(String value, String algorithm, int version) {
        this.value = value;
        this.algorithm = algorithm;
        this.version = version;
    }

    public static BlindIndex of(String value) {
        Objects.requireNonNull(value, "Blind index value cannot be null");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("Blind index value cannot be empty");
        }
        return new BlindIndex(value, "HMAC-SHA256", 1);
    }

    public String getValue() {
        return value;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getVersion() {
        return version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BlindIndex that = (BlindIndex) o;
        return version == that.version &&
                Objects.equals(value, that.value) &&
                Objects.equals(algorithm, that.algorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value, algorithm, version);
    }

    @Override
    public String toString() {
        return "BlindIndex{algorithm=" + algorithm + ", version=" + version + "}";
    }
}
