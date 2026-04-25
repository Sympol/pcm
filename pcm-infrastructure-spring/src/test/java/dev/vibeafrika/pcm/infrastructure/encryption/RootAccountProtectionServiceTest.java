package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RootAccountProtectionService}.
 *
 * <p>Validates :
 * <ul>
 *   <li>Root account access generates CRITICAL alerts</li>
 *   <li>Hardware MFA is required for root account access</li>
 *   <li>Break-glass requires dual authorization from two distinct approvers</li>
 *   <li>Root account is prohibited from routine KMS operations</li>
 *   <li>SCP restricts root KMS access</li>
 *   <li>Weekly log review is audited</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RootAccountProtectionServiceTest {

    @Mock
    private IAuditLogger auditLogger;

    private RbacAccessController rbacAccessController;

    /** Service under test – MFA configured (happy path). */
    private RootAccountProtectionService serviceWithMfa;

    /** Service under test – MFA NOT configured. */
    private RootAccountProtectionService serviceWithoutMfa;

    @BeforeEach
    void setUp() {
        when(auditLogger.logSecurityEvent(any())).thenReturn(okResult());

        rbacAccessController = new RbacAccessController(auditLogger, "root-protection-system");

        serviceWithMfa    = new RootAccountProtectionService(auditLogger, rbacAccessController, true);
        serviceWithoutMfa = new RootAccountProtectionService(auditLogger, rbacAccessController, false);
    }

    // -------------------------------------------------------------------------
    // recordRootAccountAccess – alerting 
    // -------------------------------------------------------------------------

    /**
     * Validates: 
     * Root account access must always generate a CRITICAL ROOT_ACCOUNT_ACCESS security event.
     */
    @Test
    void recordRootAccountAccess_generatesAlert_logsSecurityEvent() {
        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);

        serviceWithMfa.recordRootAccountAccess("emergency maintenance", "ops-engineer");

        verify(auditLogger, atLeastOnce()).logSecurityEvent(captor.capture());

        boolean hasRootAccessEvent = captor.getAllValues().stream()
                .anyMatch(e -> "ROOT_ACCOUNT_ACCESS".equals(e.getEventType())
                        && "CRITICAL".equals(e.getSeverity()));
        assertTrue(hasRootAccessEvent,
                "Expected a CRITICAL ROOT_ACCOUNT_ACCESS security event to be logged");
    }

    // -------------------------------------------------------------------------
    // recordRootAccountAccess – MFA enforcement 
    // -------------------------------------------------------------------------

    /**
     * Validates: 
     * When hardware MFA is not configured, root account access must be denied.
     */
    @Test
    void recordRootAccountAccess_withoutMfa_returnsFailure() {
        Result<Unit, AccessDeniedError> result =
                serviceWithoutMfa.recordRootAccountAccess("emergency", "ops-engineer");

        assertTrue(result.isFailure(), "Access should be denied when MFA is not configured");
    }

    /**
     * Validates: 
     * When hardware MFA is configured, root account access recording succeeds.
     */
    @Test
    void recordRootAccountAccess_withMfa_returnsSuccess() {
        Result<Unit, AccessDeniedError> result =
                serviceWithMfa.recordRootAccountAccess("emergency maintenance", "ops-engineer");

        assertTrue(result.isSuccess(), "Access should succeed when MFA is configured");
    }

    // -------------------------------------------------------------------------
    // Break-glass dual authorization 
    // -------------------------------------------------------------------------

    /**
     * Validates: 
     * Initiating break-glass records a pending approval and returns success.
     */
    @Test
    void initiateBreakGlass_firstApprover_recordsPendingApproval() {
        ServiceIdentity op1 = keyOperator("operator-1");

        Result<Unit, AccessDeniedError> result =
                serviceWithMfa.initiateBreakGlass("emergency-kek-rotation", op1);

        assertTrue(result.isSuccess(), "First break-glass approval should succeed");
        assertTrue(rbacAccessController.isBreakGlassPending("emergency-kek-rotation"),
                "Break-glass should be pending after first approval");
    }

    /**
     * Validates: 
     * The same approver cannot satisfy dual authorization – second approval from
     * the same identity must be rejected.
     */
    @Test
    void approveBreakGlass_sameApprover_returnsFailure() {
        ServiceIdentity op = keyOperator("operator-1");

        serviceWithMfa.initiateBreakGlass("emergency-op", op);
        Result<Unit, AccessDeniedError> result =
                serviceWithMfa.approveBreakGlass("emergency-op", op);

        assertTrue(result.isFailure(),
                "Same approver must not satisfy dual authorization");
    }

    /**
     * Validates: 
     * Two distinct approvers complete dual authorization successfully.
     */
    @Test
    void approveBreakGlass_differentApprovers_returnsSuccess() {
        ServiceIdentity op1 = keyOperator("operator-1");
        ServiceIdentity op2 = keyOperator("operator-2");

        serviceWithMfa.initiateBreakGlass("emergency-kek-rotation", op1);
        Result<Unit, AccessDeniedError> result =
                serviceWithMfa.approveBreakGlass("emergency-kek-rotation", op2);

        assertTrue(result.isSuccess(),
                "Two distinct approvers should complete dual authorization");
        assertFalse(rbacAccessController.isBreakGlassPending("emergency-kek-rotation"),
                "Break-glass should be cleared after dual authorization");
    }

    // -------------------------------------------------------------------------
    // Routine KMS operation prohibition 
    // -------------------------------------------------------------------------

    /**
     * Validates: 
     * Root account identity must not be allowed to perform routine KMS operations.
     */
    @Test
    void isRoutineKmsOperationAllowed_rootAccount_returnsFalse() {
        ServiceIdentity rootIdentity = ServiceIdentity.machine("root-account", Set.of());

        boolean allowed = serviceWithMfa.isRoutineKmsOperationAllowed(rootIdentity);

        assertFalse(allowed, "Root account must not be allowed routine KMS operations");
    }

    /**
     * Non-root service identities are allowed routine KMS operations.
     */
    @Test
    void isRoutineKmsOperationAllowed_nonRootAccount_returnsTrue() {
        ServiceIdentity regularService = ServiceIdentity.machine("profile-service",
                Set.of(EncryptionRole.DEVELOPER));

        boolean allowed = serviceWithMfa.isRoutineKmsOperationAllowed(regularService);

        assertTrue(allowed, "Non-root service should be allowed routine KMS operations");
    }

    // -------------------------------------------------------------------------
    // SCP compliance 
    // -------------------------------------------------------------------------

    /**
     * Validates: 
     * KMS operations must be flagged as SCP-restricted for the root account.
     */
    @Test
    void validateScpCompliance_kmsOperation_returnsFalse() {
        assertFalse(serviceWithMfa.validateScpCompliance("kms:Encrypt"),
                "kms:Encrypt should be SCP-restricted");
        assertFalse(serviceWithMfa.validateScpCompliance("kms:Decrypt"),
                "kms:Decrypt should be SCP-restricted");
        assertFalse(serviceWithMfa.validateScpCompliance("kms:GenerateDataKey"),
                "kms:GenerateDataKey should be SCP-restricted");
    }

    /**
     * Non-KMS operations are not restricted by SCP.
     */
    @Test
    void validateScpCompliance_nonKmsOperation_returnsTrue() {
        assertTrue(serviceWithMfa.validateScpCompliance("s3:GetObject"),
                "Non-KMS operations should not be SCP-restricted");
    }

    // -------------------------------------------------------------------------
    // Weekly access log review 
    // -------------------------------------------------------------------------

    /**
     * Validates: 
     * Weekly log review must produce an audited security event.
     */
    @Test
    void reviewAccessLogs_logsAuditEvent() {
        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);

        serviceWithMfa.reviewAccessLogs("security-auditor");

        verify(auditLogger, atLeastOnce()).logSecurityEvent(captor.capture());

        boolean hasReviewEvent = captor.getAllValues().stream()
                .anyMatch(e -> "ROOT_ACCESS_LOG_REVIEW".equals(e.getEventType()));
        assertTrue(hasReviewEvent,
                "Expected a ROOT_ACCESS_LOG_REVIEW security event to be logged");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ServiceIdentity keyOperator(String name) {
        return ServiceIdentity.machine(name, Set.of(EncryptionRole.KEY_OPERATOR));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Result<Void, AuditError> okResult() {
        return (Result<Void, AuditError>) (Result) Result.success(Unit.unit());
    }
}
