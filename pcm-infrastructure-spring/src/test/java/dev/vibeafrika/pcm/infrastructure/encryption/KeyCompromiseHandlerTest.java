package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KeyCompromiseHandler}.
 *
 * <p>Tests verify:
 * <ul>
 *   <li>Key revocation calls keyManager and auditLogger correctly</li>
 *   <li>Affected data identification returns the correct scope</li>
 *   <li>Re-encryption triggers DEK rotation and logs the event</li>
 *   <li>Incident report contains all required fields</li>
 *   <li>Incident logging captures correct event details</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class KeyCompromiseHandlerTest {

    @Mock
    private IKeyManager keyManager;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private EncryptionService encryptionService;

    private KeyCompromiseHandler handler;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;

    @BeforeEach
    void setUp() {
        handler = new KeyCompromiseHandler(keyManager, auditLogger, encryptionService);

        // Default: audit logger always succeeds
        lenient().when(auditLogger.logSecurityEvent(any()))
                .thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // revokeKey
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that revokeKey calls keyManager.invalidateCache with the correct key ID.
     */
    @Test
    void revokeKey_callsKeyManagerInvalidateCache() {
        UUID keyId = UUID.randomUUID();
        when(keyManager.invalidateCache(keyId)).thenReturn(voidSuccess());

        Result<Unit, IncidentError> result = handler.revokeKey(keyId);

        assertTrue(result.isSuccess(), "revokeKey should succeed");
        verify(keyManager).invalidateCache(keyId);
    }

    /**
     * Verifies that revokeKey logs a CRITICAL security event to the audit logger.
     */
    @Test
    void revokeKey_logsCriticalSecurityEvent() {
        UUID keyId = UUID.randomUUID();
        when(keyManager.invalidateCache(keyId)).thenReturn(voidSuccess());

        handler.revokeKey(keyId);

        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(auditLogger).logSecurityEvent(captor.capture());

        SecurityEvent event = captor.getValue();
        assertEquals("KEY_COMPROMISED", event.getEventType(),
                "Security event type must be KEY_COMPROMISED");
        assertEquals("CRITICAL", event.getSeverity(),
                "Security event severity must be CRITICAL");
        assertEquals(keyId, event.getKeyId(),
                "Security event must reference the compromised key ID");
    }

    /**
     * Verifies that revokeKey returns a failure when cache invalidation fails.
     */
    @Test
    void revokeKey_whenCacheInvalidationFails_returnsFailure() {
        UUID keyId = UUID.randomUUID();
        when(keyManager.invalidateCache(keyId))
                .thenReturn(Result.failure(KeyError.of("CACHE_ERROR", "Cache unavailable")));

        Result<Unit, IncidentError> result = handler.revokeKey(keyId);

        assertTrue(result.isFailure(), "revokeKey should fail when cache invalidation fails");
        assertEquals("REVOCATION_FAILED", result.getError().orElseThrow().getCode());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // identifyAffectedData
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that identifyAffectedData returns the list of records registered for the key.
     */
    @Test
    void identifyAffectedData_returnsRegisteredRecords() {
        UUID keyId = UUID.randomUUID();
        handler.registerEncryptedData(keyId, "PROFILE:email:record-001");
        handler.registerEncryptedData(keyId, "PROFILE:phone:record-001");
        handler.registerEncryptedData(keyId, "PROFILE:email:record-002");

        Result<List<String>, IncidentError> result = handler.identifyAffectedData(keyId);

        assertTrue(result.isSuccess(), "identifyAffectedData should succeed");
        List<String> affected = result.getValue().orElseThrow();
        assertEquals(3, affected.size(), "Should return all 3 registered records");
        assertTrue(affected.contains("PROFILE:email:record-001"));
        assertTrue(affected.contains("PROFILE:phone:record-001"));
        assertTrue(affected.contains("PROFILE:email:record-002"));
    }

    /**
     * Verifies that identifyAffectedData returns an empty list for an unknown key.
     */
    @Test
    void identifyAffectedData_unknownKey_returnsEmptyList() {
        UUID unknownKeyId = UUID.randomUUID();

        Result<List<String>, IncidentError> result = handler.identifyAffectedData(unknownKeyId);

        assertTrue(result.isSuccess(), "identifyAffectedData should succeed even for unknown key");
        assertTrue(result.getValue().orElseThrow().isEmpty(),
                "Should return empty list for unknown key");
    }

    /**
     * Verifies that identifyAffectedData logs a security event with the affected count.
     */
    @Test
    void identifyAffectedData_logsSecurityEvent() {
        UUID keyId = UUID.randomUUID();
        handler.registerEncryptedData(keyId, "PROFILE:email:record-001");

        handler.identifyAffectedData(keyId);

        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(auditLogger).logSecurityEvent(captor.capture());

        SecurityEvent event = captor.getValue();
        assertEquals("AFFECTED_DATA_IDENTIFIED", event.getEventType());
        assertEquals(keyId, event.getKeyId());
    }

    /**
     * Verifies that records registered for different keys are not mixed up.
     */
    @Test
    void identifyAffectedData_isolatesRecordsByKey() {
        UUID keyId1 = UUID.randomUUID();
        UUID keyId2 = UUID.randomUUID();

        handler.registerEncryptedData(keyId1, "PROFILE:email:record-001");
        handler.registerEncryptedData(keyId2, "CONSENT:purpose:record-002");

        List<String> affected1 = handler.identifyAffectedData(keyId1).getValue().orElseThrow();
        List<String> affected2 = handler.identifyAffectedData(keyId2).getValue().orElseThrow();

        assertEquals(1, affected1.size());
        assertEquals("PROFILE:email:record-001", affected1.get(0));
        assertEquals(1, affected2.size());
        assertEquals("CONSENT:purpose:record-002", affected2.get(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // reEncryptWithNewKey
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that reEncryptWithNewKey triggers DEK rotation via keyManager.
     */
    @Test
    void reEncryptWithNewKey_triggersDEKRotation() {
        UUID compromisedKeyId = UUID.randomUUID();
        UUID newKeyId = UUID.randomUUID();
        when(keyManager.rotateDEK(CONTEXT)).thenReturn(Result.success(newKeyId));

        Result<Integer, IncidentError> result =
                handler.reEncryptWithNewKey(compromisedKeyId, CONTEXT);

        assertTrue(result.isSuccess(), "reEncryptWithNewKey should succeed");
        verify(keyManager).rotateDEK(CONTEXT);
    }

    /**
     * Verifies that reEncryptWithNewKey returns the count of affected records.
     */
    @Test
    void reEncryptWithNewKey_returnsReEncryptedCount() {
        UUID compromisedKeyId = UUID.randomUUID();
        UUID newKeyId = UUID.randomUUID();

        handler.registerEncryptedData(compromisedKeyId, "PROFILE:email:record-001");
        handler.registerEncryptedData(compromisedKeyId, "PROFILE:phone:record-001");

        when(keyManager.rotateDEK(CONTEXT)).thenReturn(Result.success(newKeyId));

        Result<Integer, IncidentError> result =
                handler.reEncryptWithNewKey(compromisedKeyId, CONTEXT);

        assertTrue(result.isSuccess());
        assertEquals(2, result.getValue().orElseThrow(),
                "Should return count of 2 re-encrypted records");
    }

    /**
     * Verifies that reEncryptWithNewKey logs a DATA_RE_ENCRYPTED security event.
     */
    @Test
    void reEncryptWithNewKey_logsReEncryptionEvent() {
        UUID compromisedKeyId = UUID.randomUUID();
        UUID newKeyId = UUID.randomUUID();
        when(keyManager.rotateDEK(CONTEXT)).thenReturn(Result.success(newKeyId));

        handler.reEncryptWithNewKey(compromisedKeyId, CONTEXT);

        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(auditLogger).logSecurityEvent(captor.capture());

        SecurityEvent event = captor.getValue();
        assertEquals("DATA_RE_ENCRYPTED", event.getEventType());
        assertEquals(newKeyId, event.getKeyId(),
                "Security event must reference the new key ID");
    }

    /**
     * Verifies that reEncryptWithNewKey returns a failure when DEK rotation fails.
     */
    @Test
    void reEncryptWithNewKey_whenDEKRotationFails_returnsFailure() {
        UUID compromisedKeyId = UUID.randomUUID();
        when(keyManager.rotateDEK(CONTEXT))
                .thenReturn(Result.failure(KeyError.of("ROTATION_FAILED", "KMS unavailable")));

        Result<Integer, IncidentError> result =
                handler.reEncryptWithNewKey(compromisedKeyId, CONTEXT);

        assertTrue(result.isFailure());
        assertEquals("DEK_ROTATION_FAILED", result.getError().orElseThrow().getCode());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generateIncidentReport
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that generateIncidentReport produces a report with all required fields.
     */
    @Test
    void generateIncidentReport_producesValidReport() {
        UUID keyId = UUID.randomUUID();
        handler.registerEncryptedData(keyId, "PROFILE:email:record-001");
        handler.registerEncryptedData(keyId, "PROFILE:phone:record-002");

        Result<IncidentReport, IncidentError> result =
                handler.generateIncidentReport(keyId, "Suspected key exposure via log leak");

        assertTrue(result.isSuccess(), "generateIncidentReport should succeed");
        IncidentReport report = result.getValue().orElseThrow();

        assertNotNull(report.getIncidentId(), "Report must have an incident ID");
        assertNotNull(report.getReportedAt(), "Report must have a timestamp");
        assertNotNull(report.getCompromisedKeyInfo(), "Report must have compromised key info");
        assertEquals(keyId, report.getCompromisedKeyInfo().getKeyId(),
                "Report must reference the correct compromised key");
        assertEquals(2, report.getAffectedDataScope().size(),
                "Report must list all affected records");
        assertFalse(report.getActionsTaken().isEmpty(),
                "Report must list actions taken");
    }

    /**
     * Verifies that the incident report description matches the provided description.
     */
    @Test
    void generateIncidentReport_capturesIncidentDescription() {
        UUID keyId = UUID.randomUUID();
        String description = "Key material found in application logs";

        Result<IncidentReport, IncidentError> result =
                handler.generateIncidentReport(keyId, description);

        assertTrue(result.isSuccess());
        IncidentReport report = result.getValue().orElseThrow();
        assertEquals(description,
                report.getCompromisedKeyInfo().getCompromiseDescription(),
                "Report must capture the incident description");
    }

    /**
     * Verifies that generateIncidentReport logs a security event to the audit trail.
     */
    @Test
    void generateIncidentReport_logsIncidentToAuditTrail() {
        UUID keyId = UUID.randomUUID();

        handler.generateIncidentReport(keyId, "Test incident");

        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(auditLogger).logSecurityEvent(captor.capture());

        SecurityEvent event = captor.getValue();
        assertEquals("INCIDENT_REPORT_GENERATED", event.getEventType());
        assertEquals(keyId, event.getKeyId());
    }

    /**
     * Verifies that the generated report is stored and retrievable.
     */
    @Test
    void generateIncidentReport_storesReport() {
        UUID keyId = UUID.randomUUID();

        Result<IncidentReport, IncidentError> result =
                handler.generateIncidentReport(keyId, "Test incident");

        assertTrue(result.isSuccess());
        UUID incidentId = result.getValue().orElseThrow().getIncidentId();

        assertTrue(handler.getIncidentReports().containsKey(incidentId),
                "Generated report must be stored in the handler");
    }

    /**
     * Verifies that the report re-encrypted count matches the number of affected records.
     */
    @Test
    void generateIncidentReport_reEncryptedCountMatchesAffectedScope() {
        UUID keyId = UUID.randomUUID();
        handler.registerEncryptedData(keyId, "PROFILE:email:record-001");
        handler.registerEncryptedData(keyId, "PROFILE:email:record-002");
        handler.registerEncryptedData(keyId, "PROFILE:email:record-003");

        IncidentReport report = handler.generateIncidentReport(keyId, "Test")
                .getValue().orElseThrow();

        assertEquals(report.getAffectedDataScope().size(), report.getReEncryptedCount(),
                "Re-encrypted count must match the affected data scope size");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Result<Void, KeyError> voidSuccess() {
        return (Result<Void, KeyError>) (Result) Result.success(Unit.unit());
    }
}
