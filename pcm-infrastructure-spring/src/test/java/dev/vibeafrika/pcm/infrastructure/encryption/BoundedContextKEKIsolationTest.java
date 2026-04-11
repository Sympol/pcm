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
 * Unit tests for bounded context KEK isolation.
 *
 * <ul>
 *   <li>16.5: The Key_Manager SHALL maintain a separate KEK for each Bounded_Context
 *       (Profile, Consent, Segment, Preference)</li>
 *   <li>16.10: The Key_Manager SHALL use a key namespace format:
 *       {environment}.{bounded_context}.{key_type}.{key_id}</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Bounded Context KEK Isolation Tests")
class BoundedContextKEKIsolationTest {

    @Mock
    private IKMSClient kmsClient;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IVCounter ivCounter;

    private KeyManager keyManager;

    private static final Environment ENV = Environment.PROD;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        keyManager = new KeyManager(kmsClient, auditLogger, new DEKCache(), ENV, ivCounter);

        AuditError noopError = AuditError.of("NOOP", "no-op");
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(Result.failure(noopError));
        lenient().when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Separate KEK per bounded context
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Each bounded context gets its own KEK (Requirement 16.5)")
    void eachBoundedContext_getsItsOwnKEK() {
        UUID profileKekId = UUID.randomUUID();
        UUID consentKekId = UUID.randomUUID();
        UUID segmentKekId = UUID.randomUUID();
        UUID preferenceKekId = UUID.randomUUID();

        when(kmsClient.generateKEK(BoundedContext.PROFILE, ENV)).thenReturn(Result.success(profileKekId));
        when(kmsClient.generateKEK(BoundedContext.CONSENT, ENV)).thenReturn(Result.success(consentKekId));
        when(kmsClient.generateKEK(BoundedContext.SEGMENT, ENV)).thenReturn(Result.success(segmentKekId));
        when(kmsClient.generateKEK(BoundedContext.PREFERENCE, ENV)).thenReturn(Result.success(preferenceKekId));

        Result<UUID, KeyError> profileResult = keyManager.initializeKEK(BoundedContext.PROFILE);
        Result<UUID, KeyError> consentResult = keyManager.initializeKEK(BoundedContext.CONSENT);
        Result<UUID, KeyError> segmentResult = keyManager.initializeKEK(BoundedContext.SEGMENT);
        Result<UUID, KeyError> preferenceResult = keyManager.initializeKEK(BoundedContext.PREFERENCE);

        assertTrue(profileResult.isSuccess());
        assertTrue(consentResult.isSuccess());
        assertTrue(segmentResult.isSuccess());
        assertTrue(preferenceResult.isSuccess());

        UUID profileKek = profileResult.getValue().orElseThrow();
        UUID consentKek = consentResult.getValue().orElseThrow();
        UUID segmentKek = segmentResult.getValue().orElseThrow();
        UUID preferenceKek = preferenceResult.getValue().orElseThrow();

        // All four contexts must have distinct KEKs
        assertNotEquals(profileKek, consentKek, "PROFILE and CONSENT must use different KEKs");
        assertNotEquals(profileKek, segmentKek, "PROFILE and SEGMENT must use different KEKs");
        assertNotEquals(profileKek, preferenceKek, "PROFILE and PREFERENCE must use different KEKs");
        assertNotEquals(consentKek, segmentKek, "CONSENT and SEGMENT must use different KEKs");
        assertNotEquals(consentKek, preferenceKek, "CONSENT and PREFERENCE must use different KEKs");
        assertNotEquals(segmentKek, preferenceKek, "SEGMENT and PREFERENCE must use different KEKs");

        // Verify KMS was called once per context
        verify(kmsClient).generateKEK(BoundedContext.PROFILE, ENV);
        verify(kmsClient).generateKEK(BoundedContext.CONSENT, ENV);
        verify(kmsClient).generateKEK(BoundedContext.SEGMENT, ENV);
        verify(kmsClient).generateKEK(BoundedContext.PREFERENCE, ENV);
    }

    @Test
    @DisplayName("DEK for PROFILE context uses PROFILE KEK, not CONSENT KEK (Requirement 16.5)")
    void profileDEK_usesProfileKEK_notConsentKEK() {
        UUID profileKekId = UUID.randomUUID();
        UUID consentKekId = UUID.randomUUID();

        when(kmsClient.generateKEK(BoundedContext.PROFILE, ENV)).thenReturn(Result.success(profileKekId));
        when(kmsClient.generateKEK(BoundedContext.CONSENT, ENV)).thenReturn(Result.success(consentKekId));
        when(kmsClient.encryptDEK(any(DEK.class), eq(profileKekId)))
                .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), profileKekId)));
        when(kmsClient.encryptDEK(any(DEK.class), eq(consentKekId)))
                .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), consentKekId)));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(profileKekId)))
                .thenReturn(Result.success(DEK.of(randomBytes(32))));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(consentKekId)))
                .thenReturn(Result.success(DEK.of(randomBytes(32))));

        keyManager.initializeKEK(BoundedContext.PROFILE);
        keyManager.initializeKEK(BoundedContext.CONSENT);

        Result<UUID, KeyError> profileDEKResult = keyManager.rotateDEK(BoundedContext.PROFILE);
        Result<UUID, KeyError> consentDEKResult = keyManager.rotateDEK(BoundedContext.CONSENT);

        assertTrue(profileDEKResult.isSuccess());
        assertTrue(consentDEKResult.isSuccess());

        UUID profileDEKId = profileDEKResult.getValue().orElseThrow();
        UUID consentDEKId = consentDEKResult.getValue().orElseThrow();

        // Retrieve DEKs and verify each uses the correct KEK
        Result<DEKWithMetadata, KeyError> profileDEK = keyManager.getDEK(profileDEKId);
        Result<DEKWithMetadata, KeyError> consentDEK = keyManager.getDEK(consentDEKId);

        assertTrue(profileDEK.isSuccess());
        assertTrue(consentDEK.isSuccess());

        assertEquals(profileKekId, profileDEK.getValue().orElseThrow().getKekId(),
                "PROFILE DEK must be encrypted with PROFILE KEK");
        assertEquals(consentKekId, consentDEK.getValue().orElseThrow().getKekId(),
                "CONSENT DEK must be encrypted with CONSENT KEK");
        assertNotEquals(profileDEK.getValue().orElseThrow().getKekId(),
                consentDEK.getValue().orElseThrow().getKekId(),
                "PROFILE and CONSENT DEKs must use different KEKs");
    }

    @Test
    @DisplayName("Rotating KEK for one context does not affect other contexts (Requirement 16.5)")
    void rotateKEK_forOneContext_doesNotAffectOtherContexts() {
        UUID profileKekId = UUID.randomUUID();
        UUID consentKekId = UUID.randomUUID();
        UUID newProfileKekId = UUID.randomUUID();

        when(kmsClient.generateKEK(BoundedContext.PROFILE, ENV))
                .thenReturn(Result.success(profileKekId))
                .thenReturn(Result.success(newProfileKekId));
        when(kmsClient.generateKEK(BoundedContext.CONSENT, ENV)).thenReturn(Result.success(consentKekId));

        keyManager.initializeKEK(BoundedContext.PROFILE);
        keyManager.initializeKEK(BoundedContext.CONSENT);

        // Reset invocation counts after setup so we can verify what happens during rotation only
        clearInvocations(kmsClient);

        // Rotate only PROFILE KEK
        when(kmsClient.generateKEK(BoundedContext.PROFILE, ENV)).thenReturn(Result.success(newProfileKekId));
        Result<UUID, KeyError> rotateResult = keyManager.rotateKEK(BoundedContext.PROFILE);
        assertTrue(rotateResult.isSuccess());
        assertEquals(newProfileKekId, rotateResult.getValue().orElseThrow());

        // CONSENT KEK namespace should still reference the original consent KEK
        String consentKekNamespace = keyManager.getKEKNamespace(consentKekId);
        assertNotNull(consentKekNamespace, "CONSENT KEK namespace must still exist after PROFILE KEK rotation");
        assertTrue(consentKekNamespace.contains("consent"),
                "CONSENT KEK namespace must still reference consent context");

        // Verify KMS was NOT asked to generate a new KEK for CONSENT during rotation
        verify(kmsClient, never()).generateKEK(eq(BoundedContext.CONSENT), any());
    }

    @Test
    @DisplayName("getActiveDEK for different contexts returns DEKs with different KEKs (Requirement 16.5)")
    void getActiveDEK_differentContexts_returnsDEKsWithDifferentKEKs() {
        UUID profileKekId = UUID.randomUUID();
        UUID segmentKekId = UUID.randomUUID();

        when(kmsClient.generateKEK(BoundedContext.PROFILE, ENV)).thenReturn(Result.success(profileKekId));
        when(kmsClient.generateKEK(BoundedContext.SEGMENT, ENV)).thenReturn(Result.success(segmentKekId));
        when(kmsClient.encryptDEK(any(DEK.class), eq(profileKekId)))
                .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), profileKekId)));
        when(kmsClient.encryptDEK(any(DEK.class), eq(segmentKekId)))
                .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), segmentKekId)));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(profileKekId)))
                .thenReturn(Result.success(DEK.of(randomBytes(32))));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(segmentKekId)))
                .thenReturn(Result.success(DEK.of(randomBytes(32))));

        keyManager.initializeKEK(BoundedContext.PROFILE);
        keyManager.initializeKEK(BoundedContext.SEGMENT);
        keyManager.rotateDEK(BoundedContext.PROFILE);
        keyManager.rotateDEK(BoundedContext.SEGMENT);

        Result<DEKWithMetadata, KeyError> profileActiveDEK = keyManager.getActiveDEK(BoundedContext.PROFILE);
        Result<DEKWithMetadata, KeyError> segmentActiveDEK = keyManager.getActiveDEK(BoundedContext.SEGMENT);

        assertTrue(profileActiveDEK.isSuccess());
        assertTrue(segmentActiveDEK.isSuccess());

        assertNotEquals(
                profileActiveDEK.getValue().orElseThrow().getKekId(),
                segmentActiveDEK.getValue().orElseThrow().getKekId(),
                "Active DEKs for different contexts must use different KEKs (Requirement 16.5)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key namespace format
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("KEK namespace follows {environment}.{bounded_context}.kek.{key_id} (Requirement 16.10)")
    void kekNamespace_followsRequiredFormat_forAllContexts() {
        BoundedContext[] contexts = BoundedContext.values();
        UUID[] kekIds = new UUID[contexts.length];

        for (int i = 0; i < contexts.length; i++) {
            kekIds[i] = UUID.randomUUID();
            when(kmsClient.generateKEK(contexts[i], ENV)).thenReturn(Result.success(kekIds[i]));
            keyManager.initializeKEK(contexts[i]);
        }

        for (int i = 0; i < contexts.length; i++) {
            String namespace = keyManager.getKEKNamespace(kekIds[i]);
            assertNotNull(namespace, "KEK namespace must not be null for context: " + contexts[i]);

            // Validate full format
            assertTrue(KeyNamespace.isValid(namespace),
                    "KEK namespace must follow {environment}.{bounded_context}.kek.{key_id} format " +
                    "for context " + contexts[i] + " but was: " + namespace);

            // Validate environment prefix
            assertTrue(namespace.startsWith("prod."),
                    "KEK namespace must start with 'prod.' for context " + contexts[i]);

            // Validate bounded context segment
            assertTrue(namespace.contains("." + contexts[i].name().toLowerCase() + "."),
                    "KEK namespace must contain '." + contexts[i].name().toLowerCase() + ".' " +
                    "but was: " + namespace);

            // Validate key type
            assertTrue(namespace.contains(".kek."),
                    "KEK namespace must contain '.kek.' but was: " + namespace);

            // Validate key ID at the end
            assertEquals(kekIds[i], KeyNamespace.extractKeyId(namespace),
                    "Key ID extracted from namespace must match the KEK ID for context " + contexts[i]);
        }
    }

    @Test
    @DisplayName("DEK namespace follows {environment}.{bounded_context}.dek.context.{key_id} (Requirement 16.10)")
    void dekNamespace_followsRequiredFormat_forAllContexts() {
        BoundedContext[] contexts = BoundedContext.values();

        for (BoundedContext context : contexts) {
            UUID kekId = UUID.randomUUID();
            when(kmsClient.generateKEK(context, ENV)).thenReturn(Result.success(kekId));
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(EncryptedDEK.of(randomBytes(48), kekId)));

            keyManager.initializeKEK(context);
            Result<UUID, KeyError> rotateResult = keyManager.rotateDEK(context);
            assertTrue(rotateResult.isSuccess(), "DEK rotation must succeed for context: " + context);

            UUID dekId = rotateResult.getValue().orElseThrow();
            String namespace = keyManager.getDEKNamespace(dekId);

            assertNotNull(namespace, "DEK namespace must not be null for context: " + context);

            // Validate full format
            assertTrue(KeyNamespace.isValid(namespace),
                    "DEK namespace must follow {environment}.{bounded_context}.{key_type}.{key_id} format " +
                    "for context " + context + " but was: " + namespace);

            // Validate environment prefix
            assertTrue(namespace.startsWith("prod."),
                    "DEK namespace must start with 'prod.' for context " + context);

            // Validate bounded context segment
            assertTrue(namespace.contains("." + context.name().toLowerCase() + "."),
                    "DEK namespace must contain '." + context.name().toLowerCase() + ".' " +
                    "but was: " + namespace);

            // Validate key ID at the end
            assertEquals(dekId, KeyNamespace.extractKeyId(namespace),
                    "Key ID extracted from namespace must match the DEK ID for context " + context);
        }
    }

    @Test
    @DisplayName("PROFILE and CONSENT KEK namespaces differ in bounded context segment (Requirement 16.10)")
    void kekNamespaces_differByBoundedContextSegment() {
        UUID profileKekId = UUID.randomUUID();
        UUID consentKekId = UUID.randomUUID();

        when(kmsClient.generateKEK(BoundedContext.PROFILE, ENV)).thenReturn(Result.success(profileKekId));
        when(kmsClient.generateKEK(BoundedContext.CONSENT, ENV)).thenReturn(Result.success(consentKekId));

        keyManager.initializeKEK(BoundedContext.PROFILE);
        keyManager.initializeKEK(BoundedContext.CONSENT);

        String profileNamespace = keyManager.getKEKNamespace(profileKekId);
        String consentNamespace = keyManager.getKEKNamespace(consentKekId);

        assertTrue(profileNamespace.contains(".profile."),
                "PROFILE KEK namespace must contain '.profile.' but was: " + profileNamespace);
        assertTrue(consentNamespace.contains(".consent."),
                "CONSENT KEK namespace must contain '.consent.' but was: " + consentNamespace);
        assertNotEquals(profileNamespace, consentNamespace,
                "PROFILE and CONSENT KEK namespaces must be different");
    }

    @Test
    @DisplayName("KeyNamespace utility generates correct format for all four bounded contexts")
    void keyNamespaceUtility_generatesCorrectFormat_forAllContexts() {
        UUID keyId = UUID.randomUUID();

        // Verify KEK namespace for each context
        assertEquals("prod.profile.kek." + keyId,
                KeyNamespace.forKEK(Environment.PROD, BoundedContext.PROFILE, keyId));
        assertEquals("prod.consent.kek." + keyId,
                KeyNamespace.forKEK(Environment.PROD, BoundedContext.CONSENT, keyId));
        assertEquals("prod.segment.kek." + keyId,
                KeyNamespace.forKEK(Environment.PROD, BoundedContext.SEGMENT, keyId));
        assertEquals("prod.preference.kek." + keyId,
                KeyNamespace.forKEK(Environment.PROD, BoundedContext.PREFERENCE, keyId));

        // Verify DEK context namespace for each context
        assertEquals("prod.profile.dek.context." + keyId,
                KeyNamespace.forContextDEK(Environment.PROD, BoundedContext.PROFILE, keyId));
        assertEquals("prod.consent.dek.context." + keyId,
                KeyNamespace.forContextDEK(Environment.PROD, BoundedContext.CONSENT, keyId));
        assertEquals("prod.segment.dek.context." + keyId,
                KeyNamespace.forContextDEK(Environment.PROD, BoundedContext.SEGMENT, keyId));
        assertEquals("prod.preference.dek.context." + keyId,
                KeyNamespace.forContextDEK(Environment.PROD, BoundedContext.PREFERENCE, keyId));

        // All namespaces must be valid
        for (BoundedContext ctx : BoundedContext.values()) {
            assertTrue(KeyNamespace.isValid(KeyNamespace.forKEK(Environment.PROD, ctx, keyId)));
            assertTrue(KeyNamespace.isValid(KeyNamespace.forContextDEK(Environment.PROD, ctx, keyId)));
            assertTrue(KeyNamespace.isValid(KeyNamespace.forUserDEK(Environment.PROD, ctx, keyId)));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
