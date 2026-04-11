package dev.vibeafrika.pcm.domain.encryption.config;

/**
 * Supported Key Management System providers.
 */
public enum KmsProvider {
    AWS_KMS,
    AZURE_KEY_VAULT,
    GCP_KMS,
    VAULT,
    HSM
}
