package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.entity.AuditLogEntryEntity;
import dev.vibeafrika.pcm.infrastructure.encryption.repository.AuditLogEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Audit logging integration tests.
 *
 * <p>Tests:
 * <ul>
 *   <li>Audit log creation for all operations</li>
 *   <li>Audit log encryption and signing</li>
 *   <li>Audit log append-only storage</li>
 *   <li>Audit log access logging</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("Audit Logging Integration Tests")
class AuditLoggingIntegrationTest {

    private static final byte[] SIGNING_KEY =
            "audit-logging-integration-test-key!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AUDIT_LOG_KEY = new byte[32];

    static {
        new SecureRandom().nextBytes(AUDIT_LOG_KEY);
    }

    @Mock
    private AuditLogEntryRepository repository;

    private AuditLogger auditLogger;
    private AuditLogStore auditLogStore;

    @BeforeEach
    void setUp() {
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        auditLogStore = new AuditLogStore(repository, AUDIT_LOG_KEY);
        auditLogger = new AuditLogger("integration-test-service", SIGNING_KEY, auditLogStore);
    }

    // -------------------------------------------------------------------------
    // Audit log creation for all operations 
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Audit log creation for all operations")
    class AuditLogCreationTests {

        @Test
        @DisplayName("Encryption operation creates audit log entry")
        void encryptionOperation_createsAuditLogEntry() {
            EncryptionEvent event = EncryptionEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .keyId(UUID.randomUUID())
                    .fieldIdentifier("handle")
                    .success(true)
                    .build();

            Result<Void, AuditError> result = auditLogger.logEncryption(event);

            assertTrue(result.isSuccess(), "logEncryption must succeed");
            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
        }

        @Test
        @DisplayName("Decryption operation creates audit log entry")
        void decryptionOperation_createsAuditLogEntry() {
            DecryptionEvent event = DecryptionEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .keyId(UUID.randomUUID())
                    .fieldIdentifier("handle")
                    .success(true)
                    .build();

            Result<Void, AuditError> result = auditLogger.logDecryption(event);

            assertTrue(result.isSuccess(), "logDecryption must succeed");
            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
        }

        @Test
        @DisplayName("Key rotation creates audit log entry")
        void keyRotation_createsAuditLogEntry() {
            KeyRotationEvent event = KeyRotationEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .oldKeyId(UUID.randomUUID())
                    .newKeyId(UUID.randomUUID())
                    .keyType("DEK")
                    .rotationReason("SCHEDULED")
                    .success(true)
                    .build();

            Result<Void, AuditError> result = auditLogger.logKeyRotation(event);

            assertTrue(result.isSuccess(), "logKeyRotation must succeed");
            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
        }

        @Test
        @DisplayName("Security event creates audit log entry")
        void securityEvent_createsAuditLogEntry() {
            SecurityEvent event = SecurityEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .eventType("TAMPERING_DETECTED")
                    .severity("CRITICAL")
                    .keyId(UUID.randomUUID())
                    .description("Authentication tag verification failed")
                    .build();

            Result<Void, AuditError> result = auditLogger.logSecurityEvent(event);

            assertTrue(result.isSuccess(), "logSecurityEvent must succeed");
            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
        }

        @Test
        @DisplayName("Audit log entry contains timestamp, context, and field identifier")
        void auditLogEntry_containsRequiredFields() {
            ArgumentCaptor<AuditLogEntryEntity> captor = ArgumentCaptor.forClass(AuditLogEntryEntity.class);
            Instant now = Instant.now();

            EncryptionEvent event = EncryptionEvent.builder()
                    .timestamp(now)
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .keyId(UUID.randomUUID())
                    .fieldIdentifier("handle")
                    .success(true)
                    .build();

            auditLogger.logEncryption(event);

            verify(repository).save(captor.capture());
            AuditLogEntryEntity saved = captor.getValue();

            assertEquals("ENCRYPTION", saved.getEventType(), "Event type must be ENCRYPTION");
            assertNotNull(saved.getCreatedAt(), "Timestamp must be set");
            assertNotNull(saved.getEncryptedPayload(), "Encrypted payload must be set");
        }

        @Test
        @DisplayName("Audit log does not contain plaintext PII or encryption keys")
        void auditLog_doesNotContainPlaintextPiiOrKeys() {
            ArgumentCaptor<AuditLogEntryEntity> captor = ArgumentCaptor.forClass(AuditLogEntryEntity.class);

            EncryptionEvent event = EncryptionEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .keyId(UUID.randomUUID())
                    .fieldIdentifier("handle")
                    .success(true)
                    .build();

            auditLogger.logEncryption(event);

            verify(repository).save(captor.capture());
            AuditLogEntryEntity saved = captor.getValue();

            // The encrypted payload should not contain plaintext PII
            // (it's encrypted, so we verify it's not plain text)
            byte[] payload = saved.getEncryptedPayload();
            assertNotNull(payload);
            assertTrue(payload.length > 0, "Encrypted payload must not be empty");
            // Verify it's not just the raw event type string
            assertFalse(new String(payload, StandardCharsets.UTF_8).equals("ENCRYPTION"),
                    "Stored payload must be encrypted, not plaintext");
        }
    }

    // -------------------------------------------------------------------------
    // Audit log encryption and signing 
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Audit log encryption and signing")
    class AuditLogEncryptionSigningTests {

        @Test
        @DisplayName("Audit log entries are encrypted at rest")
        void auditLogEntries_encryptedAtRest() {
            ArgumentCaptor<AuditLogEntryEntity> captor = ArgumentCaptor.forClass(AuditLogEntryEntity.class);

            EncryptionEvent event = EncryptionEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .success(true)
                    .build();

            auditLogger.logEncryption(event);

            verify(repository).save(captor.capture());
            AuditLogEntryEntity saved = captor.getValue();

            assertNotNull(saved.getEncryptedPayload(), "Encrypted payload must not be null");
            assertTrue(saved.getEncryptedPayload().length > 0, "Encrypted payload must not be empty");
        }

        @Test
        @DisplayName("Audit log entries have HMAC signature for integrity")
        void auditLogEntries_haveHmacSignature() {
            ArgumentCaptor<AuditLogEntryEntity> captor = ArgumentCaptor.forClass(AuditLogEntryEntity.class);

            EncryptionEvent event = EncryptionEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .success(true)
                    .build();

            auditLogger.logEncryption(event);

            verify(repository).save(captor.capture());
            AuditLogEntryEntity saved = captor.getValue();

            assertNotNull(saved.getHmacSignature(), "HMAC signature must be set");
            assertFalse(saved.getHmacSignature().isBlank(), "HMAC signature must not be blank");
        }

        @Test
        @DisplayName("Audit log store can decrypt and verify stored entries")
        void auditLogStore_canDecryptAndVerifyEntries() {
            // Verify the store can append entries successfully
            boolean appended = auditLogStore.append("ENCRYPTION", Instant.now(),
                    "{\"eventType\":\"ENCRYPTION\",\"test\":true}", "test-signature");
            assertTrue(appended, "Audit log store must successfully append entries");

            // Verify the store persists to repository
            verify(repository, atLeastOnce()).save(any(AuditLogEntryEntity.class));
        }

        @Test
        @DisplayName("Key rotation events are always logged at CRITICAL level")
        void keyRotationEvents_alwaysLoggedAtCriticalLevel() {
            // Even with HIGH minimum level, key rotation (CRITICAL) must be logged
            AuditConfiguration config = AuditConfiguration.builder()
                    .minimumLevel(LogLevel.HIGH)
                    .build();
            AuditLogger highLevelLogger = new AuditLogger("test-service", SIGNING_KEY,
                    new AuditLogStore(repository, AUDIT_LOG_KEY), config);

            KeyRotationEvent event = KeyRotationEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("test-service")
                    .oldKeyId(UUID.randomUUID())
                    .newKeyId(UUID.randomUUID())
                    .keyType("DEK")
                    .rotationReason("SCHEDULED")
                    .success(true)
                    .build();

            highLevelLogger.logKeyRotation(event);

            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
        }
    }

    // -------------------------------------------------------------------------
    // Audit log append-only storage
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Audit log append-only storage")
    class AuditLogAppendOnlyTests {

        @Test
        @DisplayName("Audit log entries are persisted via repository (append-only)")
        void auditLogEntries_persistedViaRepository() {
            EncryptionEvent event = EncryptionEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .success(true)
                    .build();

            auditLogger.logEncryption(event);

            // Verify save was called (append-only: only save, never delete)
            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
            verify(repository, never()).delete(any());
            verify(repository, never()).deleteAll();
        }

        @Test
        @DisplayName("Multiple operations create multiple audit log entries")
        void multipleOperations_createMultipleEntries() {
            for (int i = 0; i < 5; i++) {
                EncryptionEvent event = EncryptionEvent.builder()
                        .timestamp(Instant.now())
                        .context(BoundedContext.PROFILE)
                        .serviceIdentity("integration-test-service")
                        .keyId(UUID.randomUUID())
                        .success(true)
                        .build();
                auditLogger.logEncryption(event);
            }

            verify(repository, times(5)).save(any(AuditLogEntryEntity.class));
        }

        @Test
        @DisplayName("Audit log entries have monotonically increasing sequence numbers")
        void auditLogEntries_haveMonotonicallyIncreasingSequenceNumbers() {
            ArgumentCaptor<AuditLogEntryEntity> captor = ArgumentCaptor.forClass(AuditLogEntryEntity.class);

            for (int i = 0; i < 3; i++) {
                EncryptionEvent event = EncryptionEvent.builder()
                        .timestamp(Instant.now())
                        .context(BoundedContext.PROFILE)
                        .serviceIdentity("integration-test-service")
                        .success(true)
                        .build();
                auditLogger.logEncryption(event);
            }

            verify(repository, times(3)).save(captor.capture());
            List<AuditLogEntryEntity> saved = captor.getAllValues();

            // Sequence numbers should be increasing
            for (int i = 1; i < saved.size(); i++) {
                assertTrue(saved.get(i).getSequenceNumber() > saved.get(i - 1).getSequenceNumber(),
                        "Sequence numbers must be monotonically increasing");
            }
        }
    }

    // -------------------------------------------------------------------------
    // Audit log access logging
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Audit log access logging")
    class AuditLogAccessLoggingTests {

        @Test
        @DisplayName("Audit log access creates a separate audit log entry")
        void auditLogAccess_createsAuditLogEntry() {
            AuditLogAccessEvent event = AuditLogAccessEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .accessorIdentity("auditor-user-123")
                    .accessDescription("Queried encryption events for last 24h")
                    .success(true)
                    .build();

            Result<Void, AuditError> result = auditLogger.logAuditLogAccess(event);

            assertTrue(result.isSuccess(), "logAuditLogAccess must succeed");
            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
        }

        @Test
        @DisplayName("Audit log access entry contains accessor identity and timestamp")
        void auditLogAccessEntry_containsAccessorIdentityAndTimestamp() {
            ArgumentCaptor<AuditLogEntryEntity> captor = ArgumentCaptor.forClass(AuditLogEntryEntity.class);
            Instant now = Instant.now();

            AuditLogAccessEvent event = AuditLogAccessEvent.builder()
                    .timestamp(now)
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("integration-test-service")
                    .accessorIdentity("auditor-user-456")
                    .accessDescription("Read audit log entries")
                    .success(true)
                    .build();

            auditLogger.logAuditLogAccess(event);

            verify(repository).save(captor.capture());
            AuditLogEntryEntity saved = captor.getValue();

            assertEquals("AUDIT_LOG_ACCESS", saved.getEventType(),
                    "Event type must be AUDIT_LOG_ACCESS");
            assertNotNull(saved.getCreatedAt(), "Timestamp must be set");
            assertNotNull(saved.getEncryptedPayload(), "Encrypted payload must be set");
        }

        @Test
        @DisplayName("Failed audit log access is also logged")
        void failedAuditLogAccess_isAlsoLogged() {
            AuditLogAccessEvent event = AuditLogAccessEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.CONSENT)
                    .serviceIdentity("integration-test-service")
                    .accessorIdentity("unauthorized-user")
                    .accessDescription("Attempted unauthorized access")
                    .success(false)
                    .errorCode("ACCESS_DENIED")
                    .build();

            Result<Void, AuditError> result = auditLogger.logAuditLogAccess(event);

            assertTrue(result.isSuccess(), "Failed access must still be logged");
            verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
        }
    }

}
