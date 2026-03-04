package dev.vibeafrika.pcm.domain.encryption;

import java.util.Arrays;
import java.util.Objects;

/**
 * Value object representing a 96-bit Initialization Vector (IV) for AES-GCM encryption.
 * IVs are generated using a counter-based approach combining a 64-bit random base
 * with a 32-bit monotonically increasing counter.
 */
public final class IV {
    private static final int IV_LENGTH_BYTES = 12; // 96 bits
    private final byte[] value;

    private IV(byte[] value) {
        this.value = Arrays.copyOf(value, value.length);
    }

    public static IV of(byte[] value) {
        Objects.requireNonNull(value, "IV value cannot be null");
        if (value.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("IV must be exactly 96 bits (12 bytes), got " + value.length);
        }
        return new IV(value);
    }

    /**
     * Creates an IV from a 64-bit random base and 32-bit counter.
     * 
     * @param randomBase 64-bit random base value
     * @param counter 32-bit counter value
     * @return IV combining random base and counter
     */
    public static IV fromComponents(long randomBase, int counter) {
        byte[] ivBytes = new byte[IV_LENGTH_BYTES];
        
        // First 8 bytes: random base (64 bits) in big-endian
        ivBytes[0] = (byte) (randomBase >>> 56);
        ivBytes[1] = (byte) (randomBase >>> 48);
        ivBytes[2] = (byte) (randomBase >>> 40);
        ivBytes[3] = (byte) (randomBase >>> 32);
        ivBytes[4] = (byte) (randomBase >>> 24);
        ivBytes[5] = (byte) (randomBase >>> 16);
        ivBytes[6] = (byte) (randomBase >>> 8);
        ivBytes[7] = (byte) randomBase;
        
        // Last 4 bytes: counter (32 bits) in big-endian
        ivBytes[8] = (byte) (counter >>> 24);
        ivBytes[9] = (byte) (counter >>> 16);
        ivBytes[10] = (byte) (counter >>> 8);
        ivBytes[11] = (byte) counter;
        
        return new IV(ivBytes);
    }

    public byte[] getValue() {
        return Arrays.copyOf(value, value.length);
    }

    public int getLength() {
        return value.length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IV iv = (IV) o;
        return Arrays.equals(value, iv.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "IV{length=" + value.length + "}";
    }
}
