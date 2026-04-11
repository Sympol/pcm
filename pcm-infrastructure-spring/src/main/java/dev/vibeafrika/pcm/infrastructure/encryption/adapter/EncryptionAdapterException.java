package dev.vibeafrika.pcm.infrastructure.encryption.adapter;

/**
 * Unchecked exception thrown by {@link DatabaseEncryptionAdapter} when
 * encryption or decryption of a JPA entity field fails.
 *
 * <p>This exception is intentionally unchecked so that it propagates through
 * JPA lifecycle callbacks (which cannot declare checked exceptions) and is
 * caught by the transaction boundary, rolling back the operation and preventing
 * unencrypted data from being persisted.
 */
public class EncryptionAdapterException extends RuntimeException {

    public EncryptionAdapterException(String message) {
        super(message);
    }

    public EncryptionAdapterException(String message, Throwable cause) {
        super(message, cause);
    }
}
