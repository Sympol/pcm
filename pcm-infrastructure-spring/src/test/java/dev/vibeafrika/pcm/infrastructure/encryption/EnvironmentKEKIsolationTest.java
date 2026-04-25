package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for environment-specific KEK isolation.
 *
 * <ul>
 *   <li>Separate root KEK per environment</li>
 *   <li>Keys not reusable across environments</li>
 *   <li>Environment identifier included in key metadata</li>
 *   <li>Separate KMS namespaces per environment</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Environment KEK Isolation Tests")
class EnvironmentKEKIsolationTest {

    @Mock
    private IKMSClient kmsClient;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IVCounter ivCounter;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        AuditError noopError = AuditError.of("NOOP", "no-op");
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(Result.failure(noopError));
        lenient().when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Separate root KEK per environment
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("DEV and PROD KeyManagers generate separate KEKs")
    void differentEnvironments_generateSeparateKEKs() {
        UUID devKekId = UUID.randomUUID();
        UUID prodKekId = UUID.randomUUID();

        KeyManager devManager = createKeyManager(Environment.DEV);
        KeyManager prodManager = createKeyManager(Environment.PROD);

        when(kmsClient.generateKEK(CONTEXT, Environment.DEV)).thenReturn(Result.success(devKekId));
        when(kmsClient.generateKEK(CONTEXT, Environment.PROD)).thenReturn(Result.success(prodKekId));

        Result<UUID, KeyError> devResult = devManager.initializeKEK(CONTEXT);
        Result<UUID, KeyError> prodResult = prodManager.initializeKEK(CONTEXT);

        assertTrue(devResult.isSuccess());
        assertTrue(prodResult.isSuccess());

        UUID devKek = devResult.getValue().orElseThrow();
        UUID prodKek = prodResult.getValue().orElseThrow();

        // Each environment gets its own KEK
        assertNotEquals(devKek, prodKek,
            "DEV and PROD environments must use different KEKs");

        // Verify generateKEK was called with the correct environment for each
        verify(kmsClient).generateKEK(CONTEXT, Environment.DEV);
        verify(kmsClient).generateKEK(CONTEXT, Environment.PROD);
    }

    @Test
    @DisplayName("All three environments generate separate KEKs")
    void allThreeEnvironments_generateSeparateKEKs() {
        UUID devKekId = UUID.randomUUID();
        UUID stagingKekId = UUID.randomUUID();
        UUID prodKekId = UUID.randomUUID();

        KeyManager devManager = createKeyManager(Environment.DEV);
        KeyManager stagingManager = createKeyManager(Environment.STAGING);
        KeyManager prodManager = createKeyManager(Environment.PROD);

        when(kmsClient.generateKEK(CONTEXT, Environment.DEV)).thenReturn(Result.success(devKekId));
        when(kmsClient.generateKEK(CONTEXT, Environment.STAGING)).thenReturn(Result.success(stagingKekId));
        when(kmsClient.generateKEK(CONTEXT, Environment.PROD)).thenReturn(Result.success(prodKekId));

        devManager.initializeKEK(CONTEXT);
        stagingManager.initializeKEK(CONTEXT);
        prodManager.initializeKEK(CONTEXT);

        // Verify each environment called generateKEK with its own environment
        verify(kmsClient).generateKEK(CONTEXT, Environment.DEV);
        verify(kmsClient).generateKEK(CONTEXT, Environment.STAGING);
        verify(kmsClient).generateKEK(CONTEXT, Environment.PROD);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Keys not reusable across environments
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("DEK from DEV environment is rejected by PROD KeyManager")
    void dekFromDifferentEnvironment_isRejected() {
        // Set up DEV manager and create a DEK
        KeyManager devManager = createKeyManager(Environment.DEV);
        UUID devKekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.DEV)).thenReturn(Result.success(devKekId));
        when(kmsClient.encryptDEK(any(DEK.class), eq(devKekId)))
            .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), devKekId)));
        devManager.initializeKEK(CONTEXT);
        Result<UUID, KeyError> devDEKResult = devManager.rotateDEK(CONTEXT);
        assertTrue(devDEKResult.isSuccess());
        UUID devDEKId = devDEKResult.getValue().orElseThrow();

        // PROD manager should not be able to retrieve the DEV DEK
        // (it doesn't know about it - different metadata store)
        KeyManager prodManager = createKeyManager(Environment.PROD);
        Result<DEKWithMetadata, KeyError> prodGetResult = prodManager.getDEK(devDEKId);

        // PROD manager has no knowledge of DEV DEK - should return KEY_NOT_FOUND
        assertTrue(prodGetResult.isFailure(),
            "PROD KeyManager must not be able to retrieve DEV DEK");
        String errorCode = prodGetResult.getError()
            .map(KeyError::getCode)
            .orElse("");
        assertEquals("KEY_NOT_FOUND", errorCode,
            "Error should be KEY_NOT_FOUND when DEK is from different environment");
    }

    @Test
    @DisplayName("KeyManager environment is immutable after construction")
    void keyManagerEnvironment_isImmutableAfterConstruction() {
        KeyManager prodManager = createKeyManager(Environment.PROD);
        assertEquals(Environment.PROD, prodManager.getEnvironment(),
            "Environment must be fixed at construction time");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Environment identifier included in key metadata
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("DEK metadata includes environment identifier")
    void dekMetadata_includesEnvironmentIdentifier() {
        KeyManager prodManager = createKeyManager(Environment.PROD);
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.PROD)).thenReturn(Result.success(kekId));
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
            .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), kekId)));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
            .thenReturn(Result.success(DEK.of(randomBytes(32))));

        prodManager.initializeKEK(CONTEXT);
        Result<UUID, KeyError> rotateResult = prodManager.rotateDEK(CONTEXT);
        assertTrue(rotateResult.isSuccess());
        UUID dekId = rotateResult.getValue().orElseThrow();

        // Retrieve the DEK and verify environment in metadata
        Result<DEKWithMetadata, KeyError> dekResult = prodManager.getDEK(dekId);
        assertTrue(dekResult.isSuccess());
        DEKWithMetadata dekWithMetadata = dekResult.getValue().orElseThrow();

        assertEquals(Environment.PROD, dekWithMetadata.getEnvironment(),
            "DEK metadata must include environment identifier");
    }

    @Test
    @DisplayName("DEK namespace includes environment prefix")
    void dekNamespace_includesEnvironmentPrefix() {
        KeyManager prodManager = createKeyManager(Environment.PROD);
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.PROD)).thenReturn(Result.success(kekId));
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
            .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), kekId)));

        prodManager.initializeKEK(CONTEXT);
        Result<UUID, KeyError> rotateResult = prodManager.rotateDEK(CONTEXT);
        assertTrue(rotateResult.isSuccess());
        UUID dekId = rotateResult.getValue().orElseThrow();

        String namespace = prodManager.getDEKNamespace(dekId);
        assertNotNull(namespace, "DEK namespace must not be null");
        assertTrue(namespace.startsWith("prod."),
            "DEK namespace must start with environment prefix 'prod.' but was: " + namespace);
        assertTrue(namespace.contains("profile"),
            "DEK namespace must contain bounded context 'profile' but was: " + namespace);
    }

    @Test
    @DisplayName("KEK namespace includes environment prefix")
    void kekNamespace_includesEnvironmentPrefix() {
        KeyManager stagingManager = createKeyManager(Environment.STAGING);
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.STAGING)).thenReturn(Result.success(kekId));

        stagingManager.initializeKEK(CONTEXT);

        String namespace = stagingManager.getKEKNamespace(kekId);
        assertNotNull(namespace, "KEK namespace must not be null");
        assertTrue(namespace.startsWith("staging."),
            "KEK namespace must start with environment prefix 'staging.' but was: " + namespace);
        assertTrue(namespace.contains("kek"),
            "KEK namespace must contain key type 'kek' but was: " + namespace);
    }

    @Test
    @DisplayName("DEV DEK namespace starts with 'dev.'")
    void devDekNamespace_startsWithDev() {
        KeyManager devManager = createKeyManager(Environment.DEV);
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.DEV)).thenReturn(Result.success(kekId));
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
            .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), kekId)));

        devManager.initializeKEK(CONTEXT);
        Result<UUID, KeyError> rotateResult = devManager.rotateDEK(CONTEXT);
        assertTrue(rotateResult.isSuccess());
        UUID dekId = rotateResult.getValue().orElseThrow();

        String namespace = devManager.getDEKNamespace(dekId);
        assertNotNull(namespace);
        assertTrue(namespace.startsWith("dev."),
            "DEV DEK namespace must start with 'dev.' but was: " + namespace);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Separate KMS namespaces per environment
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("generateKEK is called with correct environment for KMS namespace isolation")
    void generateKEK_calledWithCorrectEnvironment_forKMSNamespaceIsolation() {
        KeyManager prodManager = createKeyManager(Environment.PROD);
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.PROD)).thenReturn(Result.success(kekId));

        prodManager.initializeKEK(CONTEXT);

        // Verify KMS was called with PROD environment - this ensures separate KMS namespace
        verify(kmsClient).generateKEK(CONTEXT, Environment.PROD);
        // Verify KMS was NOT called with other environments
        verify(kmsClient, never()).generateKEK(CONTEXT, Environment.DEV);
        verify(kmsClient, never()).generateKEK(CONTEXT, Environment.STAGING);
    }

    @Test
    @DisplayName("rotateKEK passes environment to KMS for namespace isolation")
    void rotateKEK_passesEnvironmentToKMS() {
        KeyManager prodManager = createKeyManager(Environment.PROD);
        UUID oldKekId = UUID.randomUUID();
        UUID newKekId = UUID.randomUUID();

        when(kmsClient.generateKEK(CONTEXT, Environment.PROD))
            .thenReturn(Result.success(oldKekId))
            .thenReturn(Result.success(newKekId));

        prodManager.initializeKEK(CONTEXT);
        Result<UUID, KeyError> rotateResult = prodManager.rotateKEK(CONTEXT);

        assertTrue(rotateResult.isSuccess());
        // Both KEK generations should use PROD environment
        verify(kmsClient, times(2)).generateKEK(CONTEXT, Environment.PROD);
        verify(kmsClient, never()).generateKEK(eq(CONTEXT), eq(Environment.DEV));
        verify(kmsClient, never()).generateKEK(eq(CONTEXT), eq(Environment.STAGING));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key Namespace Format 
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("DEK namespace follows format {environment}.{bounded_context}.{key_type}.{key_id}")
    void dekNamespace_followsRequiredFormat() {
        KeyManager prodManager = createKeyManager(Environment.PROD);
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.PROD)).thenReturn(Result.success(kekId));
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
            .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), kekId)));

        prodManager.initializeKEK(CONTEXT);
        Result<UUID, KeyError> rotateResult = prodManager.rotateDEK(CONTEXT);
        assertTrue(rotateResult.isSuccess());
        UUID dekId = rotateResult.getValue().orElseThrow();

        String namespace = prodManager.getDEKNamespace(dekId);
        assertNotNull(namespace);

        // Validate namespace format: {environment}.{bounded_context}.{key_type}.{key_id}
        assertTrue(KeyNamespace.isValid(namespace),
            "DEK namespace must follow format {environment}.{bounded_context}.{key_type}.{key_id} " +
            "but was: " + namespace);

        // Verify environment can be extracted from namespace
        Environment extractedEnv = KeyNamespace.extractEnvironment(namespace);
        assertEquals(Environment.PROD, extractedEnv,
            "Environment extracted from namespace must match configured environment");

        // Verify key ID can be extracted from namespace
        UUID extractedKeyId = KeyNamespace.extractKeyId(namespace);
        assertEquals(dekId, extractedKeyId,
            "Key ID extracted from namespace must match the DEK ID");
    }

    @Test
    @DisplayName("KEK namespace follows format {environment}.{bounded_context}.kek.{key_id}")
    void kekNamespace_followsRequiredFormat() {
        KeyManager prodManager = createKeyManager(Environment.PROD);
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, Environment.PROD)).thenReturn(Result.success(kekId));

        prodManager.initializeKEK(CONTEXT);

        String namespace = prodManager.getKEKNamespace(kekId);
        assertNotNull(namespace);

        // Validate namespace format
        assertTrue(KeyNamespace.isValid(namespace),
            "KEK namespace must follow format {environment}.{bounded_context}.kek.{key_id} " +
            "but was: " + namespace);

        // Verify it contains "kek" as key type
        assertTrue(namespace.contains(".kek."),
            "KEK namespace must contain '.kek.' but was: " + namespace);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // KeyNamespace utility tests
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("KeyNamespace.forKEK generates correct format")
    void keyNamespace_forKEK_generatesCorrectFormat() {
        UUID keyId = UUID.randomUUID();
        String namespace = KeyNamespace.forKEK(Environment.PROD, BoundedContext.PROFILE, keyId);

        assertEquals("prod.profile.kek." + keyId, namespace);
        assertTrue(KeyNamespace.isValid(namespace));
    }

    @Test
    @DisplayName("KeyNamespace.forContextDEK generates correct format")
    void keyNamespace_forContextDEK_generatesCorrectFormat() {
        UUID keyId = UUID.randomUUID();
        String namespace = KeyNamespace.forContextDEK(Environment.STAGING, BoundedContext.CONSENT, keyId);

        assertEquals("staging.consent.dek.context." + keyId, namespace);
        assertTrue(KeyNamespace.isValid(namespace));
    }

    @Test
    @DisplayName("KeyNamespace.forUserDEK generates correct format")
    void keyNamespace_forUserDEK_generatesCorrectFormat() {
        UUID keyId = UUID.randomUUID();
        String namespace = KeyNamespace.forUserDEK(Environment.DEV, BoundedContext.SEGMENT, keyId);

        assertEquals("dev.segment.dek.user." + keyId, namespace);
        assertTrue(KeyNamespace.isValid(namespace));
    }

    @Test
    @DisplayName("KeyNamespace.isValid rejects invalid formats")
    void keyNamespace_isValid_rejectsInvalidFormats() {
        assertFalse(KeyNamespace.isValid(null));
        assertFalse(KeyNamespace.isValid(""));
        assertFalse(KeyNamespace.isValid("invalid"));
        assertFalse(KeyNamespace.isValid("prod.profile.kek")); // missing key ID
        assertFalse(KeyNamespace.isValid("PROD.profile.kek." + UUID.randomUUID())); // uppercase env
        assertFalse(KeyNamespace.isValid("prod.profile.unknown." + UUID.randomUUID())); // unknown key type
    }

    @Test
    @DisplayName("KeyNamespace.extractEnvironment returns correct environment")
    void keyNamespace_extractEnvironment_returnsCorrectEnvironment() {
        UUID keyId = UUID.randomUUID();
        assertEquals(Environment.PROD, KeyNamespace.extractEnvironment("prod.profile.kek." + keyId));
        assertEquals(Environment.DEV, KeyNamespace.extractEnvironment("dev.profile.kek." + keyId));
        assertEquals(Environment.STAGING, KeyNamespace.extractEnvironment("staging.profile.kek." + keyId));
    }

    @Test
    @DisplayName("KeyNamespace.extractKeyId returns correct UUID")
    void keyNamespace_extractKeyId_returnsCorrectUUID() {
        UUID keyId = UUID.randomUUID();
        String namespace = "prod.profile.kek." + keyId;
        assertEquals(keyId, KeyNamespace.extractKeyId(namespace));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private KeyManager createKeyManager(Environment environment) {
        return new KeyManager(kmsClient, auditLogger, new DEKCache(), environment, ivCounter);
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
