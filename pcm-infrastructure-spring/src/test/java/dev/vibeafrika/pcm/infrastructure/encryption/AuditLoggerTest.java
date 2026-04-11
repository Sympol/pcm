package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.entity.AuditLogEntryEntity;
import dev.vibeafrika.pcm.infrastructure.encryption.repository.AuditLogEntryRepository;
import org.junit.jupiter.api.BeforeEach;
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
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AuditLogger}.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>All five log methods return a successful Result</li>
 *   <li>Null event arguments are rejected with NullPointerException</li>
 *   <li>When an AuditLogStore is provided, entries are persisted to it</li>
 *   <li>The HMAC signature embedded in the log entry is extracted and stored</li>
 *   <li>The implementation never exposes plaintext PII or key material
 *       (structural check: the class compiles and runs without touching
 *       plaintext fields that don't exist on the event types)</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuditLoggerTest {

    private static final byte[] SIGNING_KEY =
            "test-signing-key-32-bytes-padded!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AUDIT_LOG_KEY = new byte[32];

    static {
        new SecureRandom().nextBytes(AUDIT_LOG_KEY);
    }

    @Mock
    private AuditLogEntryRepository repository;

    private AuditLogger auditLogger;
    private AuditLogger auditLoggerWithStore;

    @BeforeEach
    void setUp() {
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        auditLogger = new AuditLogger("test-service", SIGNING_KEY);
        AuditLogStore store = new AuditLogStore(repository, AUDIT_LOG_KEY);
        auditLoggerWithStore = new AuditLogger("test-service", SIGNING_KEY, store);
    }

    // -------------------------------------------------------------------------
    // logEncryption
    // -------------------------------------------------------------------------

    @Test
    void logEncryption_success_returnsSuccessResult() {
        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .keyId(UUID.randomUUID())
                .fieldIdentifier("email")
                .success(true)
                .build();

        Result<Void, AuditError> result = auditLogger.logEncryption(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logEncryption_failure_returnsSuccessResult() {
        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.CONSENT)
                .serviceIdentity("test-service")
                .success(false)
                .errorCode("ENCRYPTION_FAILED")
                .build();

        Result<Void, AuditError> result = auditLogger.logEncryption(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logEncryption_nullEvent_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> auditLogger.logEncryption(null));
    }

    // -------------------------------------------------------------------------
    // logDecryption
    // -------------------------------------------------------------------------

    @Test
    void logDecryption_success_returnsSuccessResult() {
        DecryptionEvent event = DecryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.SEGMENT)
                .serviceIdentity("test-service")
                .keyId(UUID.randomUUID())
                .fieldIdentifier("phone")
                .success(true)
                .build();

        Result<Void, AuditError> result = auditLogger.logDecryption(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logDecryption_failure_returnsSuccessResult() {
        DecryptionEvent event = DecryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PREFERENCE)
                .serviceIdentity("test-service")
                .success(false)
                .errorCode("DECRYPTION_FAILED")
                .build();

        Result<Void, AuditError> result = auditLogger.logDecryption(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logDecryption_nullEvent_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> auditLogger.logDecryption(null));
    }

    // -------------------------------------------------------------------------
    // logKeyRotation
    // -------------------------------------------------------------------------

    @Test
    void logKeyRotation_returnsSuccessResult() {
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

        Result<Void, AuditError> result = auditLogger.logKeyRotation(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logKeyRotation_nullEvent_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> auditLogger.logKeyRotation(null));
    }

    // -------------------------------------------------------------------------
    // logSecurityEvent
    // -------------------------------------------------------------------------

    @Test
    void logSecurityEvent_critical_returnsSuccessResult() {
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .eventType("TAMPERING_DETECTED")
                .severity("CRITICAL")
                .keyId(UUID.randomUUID())
                .description("Authentication tag verification failed")
                .build();

        Result<Void, AuditError> result = auditLogger.logSecurityEvent(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logSecurityEvent_high_returnsSuccessResult() {
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.CONSENT)
                .serviceIdentity("test-service")
                .eventType("UNAUTHORIZED_ACCESS")
                .severity("HIGH")
                .description("Unauthorized key access attempt")
                .build();

        Result<Void, AuditError> result = auditLogger.logSecurityEvent(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logSecurityEvent_nullEvent_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> auditLogger.logSecurityEvent(null));
    }

    // -------------------------------------------------------------------------
    // logKeyAccess
    // -------------------------------------------------------------------------

    @Test
    void logKeyAccess_returnsSuccessResult() {
        KeyAccessEvent event = KeyAccessEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .keyId(UUID.randomUUID())
                .keyType("DEK")
                .accessType("CACHE_HIT")
                .success(true)
                .build();

        Result<Void, AuditError> result = auditLogger.logKeyAccess(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logKeyAccess_nullEvent_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> auditLogger.logKeyAccess(null));
    }

    // -------------------------------------------------------------------------
    // logAuditLogAccess
    // -------------------------------------------------------------------------

    @Test
    void logAuditLogAccess_success_returnsSuccessResult() {
        AuditLogAccessEvent event = AuditLogAccessEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .accessorIdentity("auditor-user-123")
                .accessDescription("Queried encryption events for last 24h")
                .success(true)
                .build();

        Result<Void, AuditError> result = auditLogger.logAuditLogAccess(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logAuditLogAccess_failure_returnsSuccessResult() {
        AuditLogAccessEvent event = AuditLogAccessEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.CONSENT)
                .serviceIdentity("test-service")
                .accessorIdentity("auditor-user-456")
                .accessDescription("Attempted to query audit logs")
                .success(false)
                .errorCode("ACCESS_DENIED")
                .build();

        Result<Void, AuditError> result = auditLogger.logAuditLogAccess(event);

        assertTrue(result.isSuccess());
    }

    @Test
    void logAuditLogAccess_nullEvent_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> auditLogger.logAuditLogAccess(null));
    }

    @Test
    void logAuditLogAccess_withStore_persistsEncryptedEntry() {
        AuditLogAccessEvent event = AuditLogAccessEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .accessorIdentity("auditor-user-789")
                .accessDescription("Read audit log entries")
                .success(true)
                .build();

        Result<Void, AuditError> result = auditLoggerWithStore.logAuditLogAccess(event);

        assertTrue(result.isSuccess());
        verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
    }

    @Test
    void logAuditLogAccess_entryContainsAccessorIdentityAndTimestamp() {
        ArgumentCaptor<AuditLogEntryEntity> captor =
                ArgumentCaptor.forClass(AuditLogEntryEntity.class);

        Instant now = Instant.now();
        AuditLogAccessEvent event = AuditLogAccessEvent.builder()
                .timestamp(now)
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .accessorIdentity("auditor-user-abc")
                .accessDescription("Queried key rotation events")
                .success(true)
                .build();

        auditLoggerWithStore.logAuditLogAccess(event);

        verify(repository).save(captor.capture());
        AuditLogEntryEntity saved = captor.getValue();

        // The event type must be AUDIT_LOG_ACCESS
        assertEquals("AUDIT_LOG_ACCESS", saved.getEventType());
        // The timestamp must be recorded
        assertNotNull(saved.getCreatedAt());
        // The stored payload must be encrypted (non-empty)
        assertNotNull(saved.getEncryptedPayload());
        assertTrue(saved.getEncryptedPayload().length > 0);
    }

    // -------------------------------------------------------------------------
    // Metadata handling
    // -------------------------------------------------------------------------

    @Test
    void logEncryption_withMetadata_returnsSuccessResult() {
        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .success(true)
                .metadata(Map.of("batchSize", 10, "algorithm", "AES-256-GCM"))
                .build();

        Result<Void, AuditError> result = auditLogger.logEncryption(event);

        assertTrue(result.isSuccess());
    }

    // -------------------------------------------------------------------------
    // Encrypted append-only store integration
    // -------------------------------------------------------------------------

    @Test
    void logEncryption_withStore_persistsEncryptedEntry() {
        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .keyId(UUID.randomUUID())
                .fieldIdentifier("email")
                .success(true)
                .build();

        Result<Void, AuditError> result = auditLoggerWithStore.logEncryption(event);

        assertTrue(result.isSuccess());
        verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
    }

    @Test
    void logDecryption_withStore_persistsEncryptedEntry() {
        DecryptionEvent event = DecryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.SEGMENT)
                .serviceIdentity("test-service")
                .keyId(UUID.randomUUID())
                .fieldIdentifier("phone")
                .success(true)
                .build();

        Result<Void, AuditError> result = auditLoggerWithStore.logDecryption(event);

        assertTrue(result.isSuccess());
        verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
    }

    @Test
    void logKeyRotation_withStore_persistsEncryptedEntry() {
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

        Result<Void, AuditError> result = auditLoggerWithStore.logKeyRotation(event);

        assertTrue(result.isSuccess());
        verify(repository, times(1)).save(any(AuditLogEntryEntity.class));
    }

    @Test
    void logEncryption_withStore_storedPayloadIsEncrypted() {
        ArgumentCaptor<AuditLogEntryEntity> captor =
                ArgumentCaptor.forClass(AuditLogEntryEntity.class);

        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .success(true)
                .build();

        auditLoggerWithStore.logEncryption(event);

        verify(repository).save(captor.capture());
        AuditLogEntryEntity saved = captor.getValue();

        // The stored payload must not be empty
        assertNotNull(saved.getEncryptedPayload());
        assertTrue(saved.getEncryptedPayload().length > 0);

        // The stored payload must not equal the raw string "ENCRYPTION"
        assertFalse(Arrays.equals("ENCRYPTION".getBytes(StandardCharsets.UTF_8),
                saved.getEncryptedPayload()),
                "Stored payload must be encrypted");
    }

    @Test
    void logEncryption_withStore_storedEntryHasHmacSignature() {
        ArgumentCaptor<AuditLogEntryEntity> captor =
                ArgumentCaptor.forClass(AuditLogEntryEntity.class);

        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .success(true)
                .build();

        auditLoggerWithStore.logEncryption(event);

        verify(repository).save(captor.capture());
        AuditLogEntryEntity saved = captor.getValue();

        assertNotNull(saved.getHmacSignature());
        assertFalse(saved.getHmacSignature().isBlank(),
                "Stored entry must have a non-blank HMAC signature");
    }

    @Test
    void logEncryption_withoutStore_doesNotCallRepository() {
        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .success(true)
                .build();

        // auditLogger has no store
        auditLogger.logEncryption(event);

        verifyNoInteractions(repository);
    }

    // -------------------------------------------------------------------------
    // Configurable audit logging levels 
    // -------------------------------------------------------------------------

    @Test
    void logEncryption_belowMinimumLevel_isFiltered() {
        // Configure minimum level HIGH – MEDIUM encryption events should be filtered
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.HIGH)
                .build();
        AuditLogger highLevelLogger = new AuditLogger("test-service", SIGNING_KEY,
                new AuditLogStore(repository, AUDIT_LOG_KEY), config);

        EncryptionEvent event = EncryptionEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .success(true)
                .build();

        Result<Void, AuditError> result = highLevelLogger.logEncryption(event);

        // Returns success but does NOT persist (filtered out)
        assertTrue(result.isSuccess());
        verifyNoInteractions(repository);
    }

    @Test
    void logKeyRotation_alwaysLoggedRegardlessOfMinimumLevel_critical(
    ) {
        // Configure minimum level CRITICAL – key rotation is CRITICAL so it must still be logged
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.CRITICAL)
                .build();
        AuditLogger criticalLogger = new AuditLogger("test-service", SIGNING_KEY,
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

        Result<Void, AuditError> result = criticalLogger.logKeyRotation(event);

        // Key rotation is CRITICAL – always logged 
        assertTrue(result.isSuccess());
        verify(repository, times(1)).save(any());
    }

    @Test
    void logKeyRotation_alwaysLoggedEvenWhenMinimumLevelIsHigh() {
        // Configure minimum level HIGH – key rotation (CRITICAL) must still be logged
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
                .rotationReason("EMERGENCY")
                .success(true)
                .build();

        Result<Void, AuditError> result = highLevelLogger.logKeyRotation(event);

        // CRITICAL events are always logged regardless of minimum level 
        assertTrue(result.isSuccess());
        verify(repository, times(1)).save(any());
    }

    @Test
    void logSecurityEvent_authenticationFailure_loggedAtHighLevel() {
        // Configure minimum level HIGH – authentication failures must be logged at HIGH
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.HIGH)
                .build();
        AuditLogger highLevelLogger = new AuditLogger("test-service", SIGNING_KEY,
                new AuditLogStore(repository, AUDIT_LOG_KEY), config);

        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .eventType("AUTHENTICATION_FAILED")
                .severity("HIGH")
                .description("Authentication failure detected")
                .build();

        Result<Void, AuditError> result = highLevelLogger.logSecurityEvent(event);

        // Authentication failures are HIGH – logged when minimum is HIGH 
        assertTrue(result.isSuccess());
        verify(repository, times(1)).save(any());
    }

    @Test
    void logSecurityEvent_authenticationFailure_filteredWhenMinimumIsCritical() {
        // Configure minimum level CRITICAL – HIGH auth failures should be filtered
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.CRITICAL)
                .build();
        AuditLogger criticalLogger = new AuditLogger("test-service", SIGNING_KEY,
                new AuditLogStore(repository, AUDIT_LOG_KEY), config);

        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity("test-service")
                .eventType("AUTHENTICATION_FAILED")
                .severity("HIGH")
                .description("Authentication failure detected")
                .build();

        Result<Void, AuditError> result = criticalLogger.logSecurityEvent(event);

        // HIGH events are filtered when minimum is CRITICAL
        assertTrue(result.isSuccess());
        verifyNoInteractions(repository);
    }

    @Test
    void logKeyAccess_withSampling_logsOnlyEveryNthEvent() {
        // Configure sampling rate 3 for LOW level events
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.LOW)
                .samplingRate(3)
                .sampledLevels(java.util.Set.of(LogLevel.LOW))
                .build();
        AuditLogger samplingLogger = new AuditLogger("test-service", SIGNING_KEY,
                new AuditLogStore(repository, AUDIT_LOG_KEY), config);

        // Log 3 key access events (LOW level)
        for (int i = 0; i < 3; i++) {
            KeyAccessEvent event = KeyAccessEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("test-service")
                    .keyId(UUID.randomUUID())
                    .keyType("DEK")
                    .accessType("CACHE_HIT")
                    .success(true)
                    .build();
            samplingLogger.logKeyAccess(event);
        }

        // With rate=3, only the 1st event is logged (1st, 4th, 7th, ...)
        verify(repository, times(1)).save(any());
    }

    @Test
    void logKeyAccess_withSamplingRateOne_logsAllEvents() {
        // Default sampling rate = 1 means log all events
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.LOW)
                .samplingRate(1)
                .build();
        AuditLogger noSamplingLogger = new AuditLogger("test-service", SIGNING_KEY,
                new AuditLogStore(repository, AUDIT_LOG_KEY), config);

        for (int i = 0; i < 3; i++) {
            KeyAccessEvent event = KeyAccessEvent.builder()
                    .timestamp(Instant.now())
                    .context(BoundedContext.PROFILE)
                    .serviceIdentity("test-service")
                    .keyId(UUID.randomUUID())
                    .keyType("DEK")
                    .accessType("CACHE_HIT")
                    .success(true)
                    .build();
            noSamplingLogger.logKeyAccess(event);
        }

        // All 3 events logged
        verify(repository, times(3)).save(any());
    }

    @Test
    void shouldLog_criticalLevel_alwaysTrue() {
        // Even with minimum level CRITICAL, CRITICAL events are always logged
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.CRITICAL)
                .build();
        AuditLogger logger = new AuditLogger("test-service", SIGNING_KEY, null, config);

        assertTrue(logger.shouldLog(LogLevel.CRITICAL));
    }

    @Test
    void shouldLog_lowLevelBelowMinimum_returnsFalse() {
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.HIGH)
                .build();
        AuditLogger logger = new AuditLogger("test-service", SIGNING_KEY, null, config);

        assertFalse(logger.shouldLog(LogLevel.LOW));
        assertFalse(logger.shouldLog(LogLevel.MEDIUM));
    }

    @Test
    void shouldLog_highLevelAtMinimumHigh_returnsTrue() {
        AuditConfiguration config = AuditConfiguration.builder()
                .minimumLevel(LogLevel.HIGH)
                .build();
        AuditLogger logger = new AuditLogger("test-service", SIGNING_KEY, null, config);

        assertTrue(logger.shouldLog(LogLevel.HIGH));
    }

    @Test
    void auditConfiguration_defaults_areCorrect() {
        AuditConfiguration config = AuditConfiguration.defaults();

        assertEquals(LogLevel.LOW, config.getMinimumLevel());
        assertEquals(1, config.getSamplingRate());
        assertTrue(config.getSampledLevels().contains(LogLevel.LOW));
    }

    @Test
    void logLevel_isAtLeast_criticalAlwaysTrue() {
        // CRITICAL is always at least any level
        for (LogLevel level : LogLevel.values()) {
            assertTrue(LogLevel.CRITICAL.isAtLeast(level),
                    "CRITICAL should be at least " + level);
        }
    }

    @Test
    void logLevel_isAtLeast_lowBelowHigh_returnsFalse() {
        assertFalse(LogLevel.LOW.isAtLeast(LogLevel.HIGH));
        assertFalse(LogLevel.LOW.isAtLeast(LogLevel.MEDIUM));
        assertFalse(LogLevel.MEDIUM.isAtLeast(LogLevel.HIGH));
    }

    @Test
    void accessType_hasSystemAndHumanValues() {
        // distinguish system and human access
        assertNotNull(AccessType.SYSTEM);
        assertNotNull(AccessType.HUMAN);
    }
}
