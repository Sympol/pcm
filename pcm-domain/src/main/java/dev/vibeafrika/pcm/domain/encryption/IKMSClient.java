package dev.vibeafrika.pcm.domain.encryption;

import java.util.UUID;

/**
 * Domain interface for interacting with Key Management Systems (KMS) or Hardware Security Modules (HSM).
 * 
 * <p>The KMS Client is responsible for:
 * <ul>
 *   <li>Encrypting DEKs with KEKs (envelope encryption)</li>
 *   <li>Decrypting encrypted DEKs using KEKs</li>
 *   <li>Generating new KEKs in the KMS</li>
 *   <li>Health checking KMS availability</li>
 * </ul>
 * 
 * <p>KEKs (Key Encryption Keys) never leave the KMS/HSM secure boundary.
 * Only encrypted DEKs are transmitted to the application.
 * 
 * <p>Supported KMS providers:
 * <ul>
 *   <li>AWS KMS</li>
 *   <li>Azure Key Vault</li>
 *   <li>GCP Cloud KMS</li>
 *   <li>HashiCorp Vault</li>
 *   <li>On-premise HSM</li>
 * </ul>
 * 
 */
public interface IKMSClient {

    /**
     * Encrypts a DEK using the specified KEK.
     * 
     * <p>The KEK never leaves the KMS/HSM. The encryption operation happens
     * within the secure boundary of the KMS.
     * 
     * <p>This method is used during:
     * <ul>
     *   <li>Initial DEK generation</li>
     *   <li>DEK rotation</li>
     *   <li>KEK rotation (re-encrypting DEKs with new KEK)</li>
     * </ul>
     * 
     * @param dek the Data Encryption Key to encrypt
     * @param kekId the UUID of the Key Encryption Key to use
     * @return Result containing the encrypted DEK, or KMSError if encryption fails
     */
    Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId);

    /**
     * Decrypts an encrypted DEK using the specified KEK.
     * 
     * <p>The KEK never leaves the KMS/HSM. The decryption operation happens
     * within the secure boundary of the KMS.
     * 
     * <p>This method is used during:
     * <ul>
     *   <li>Cache miss when retrieving a DEK</li>
     *   <li>Application startup when loading active DEKs</li>
     *   <li>Decryption operations with rotated DEKs</li>
     * </ul>
     * 
     * @param encryptedDEK the encrypted Data Encryption Key
     * @param kekId the UUID of the Key Encryption Key to use
     * @return Result containing the decrypted DEK, or KMSError if decryption fails
     */
    Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId);

    /**
     * Generates a new KEK in the KMS for the specified context and environment.
     * 
     * <p>The KEK is generated within the KMS/HSM and never leaves the secure boundary.
     * Only the KEK identifier (UUID) is returned to the application.
     * 
     * <p>KEK naming convention: {environment}.{bounded_context}.kek.{uuid}
     * 
     * <p>This method is used during:
     * <ul>
     *   <li>Initial system setup</li>
     *   <li>KEK rotation</li>
     *   <li>Adding new bounded contexts</li>
     * </ul>
     * 
     * @param context the bounded context (Profile, Consent, Segment, or Preference)
     * @param environment the environment (DEV, STAGING, or PROD)
     * @return Result containing the new KEK's UUID, or KMSError if generation fails
     */
    Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment);

    /**
     * Checks the health and availability of the KMS.
     * 
     * <p>This method is used for:
     * <ul>
     *   <li>Circuit breaker health checks</li>
     *   <li>Monitoring and alerting</li>
     *   <li>Failover detection</li>
     * </ul>
     * 
     * <p>The health check should verify:
     * <ul>
     *   <li>KMS connectivity</li>
     *   <li>Authentication validity</li>
     *   <li>Authorization permissions</li>
     *   <li>KMS service availability</li>
     * </ul>
     * 
     * @return Result containing KMS health status, or KMSError if health check fails
     */
    Result<KMSHealth, KMSError> healthCheck();
}
