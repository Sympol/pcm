package dev.vibeafrika.pcm.infrastructure.spring.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.RbacAccessController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RbacAccessController}.
 *
 * <p>Covers Requirements :
 * <ul>
 *   <li>Role permissions are correctly enforced</li>
 *   <li>Unauthorized access is denied and logged</li>
 *   <li>Human identities are always rejected</li>
 *   <li>Separation of duties constraints are upheld</li>
 *   <li>Dual authorization for break-glass procedures</li>
 * </ul>
 */
class RbacAccessControllerTest {

    private CapturingAuditLogger auditLogger;
    private RbacAccessController controller;

    @BeforeEach
    void setUp() {
        auditLogger = new CapturingAuditLogger();
        controller = new RbacAccessController(auditLogger, "test-system");
    }

    // =========================================================================
    // Role permission tests
    // =========================================================================

    @Nested
    class RolePermissionTests {

        @Test
        void cryptoAdmin_canConfigureKmsPolicy() {
            ServiceIdentity admin = machine("admin-svc", EncryptionRole.CRYPTO_ADMIN);
            assertGranted(admin, EncryptionPermission.CONFIGURE_KMS_POLICY);
        }

        @Test
        void cryptoAdmin_canViewKeyMetadata() {
            ServiceIdentity admin = machine("admin-svc", EncryptionRole.CRYPTO_ADMIN);
            assertGranted(admin, EncryptionPermission.VIEW_KEY_METADATA);
        }

        @Test
        void cryptoAdmin_canViewAuditLogs() {
            ServiceIdentity admin = machine("admin-svc", EncryptionRole.CRYPTO_ADMIN);
            assertGranted(admin, EncryptionPermission.VIEW_AUDIT_LOGS);
        }

        @Test
        void keyOperator_canRotateDek() {
            ServiceIdentity operator = machine("operator-svc", EncryptionRole.KEY_OPERATOR);
            assertGranted(operator, EncryptionPermission.ROTATE_DEK);
        }

        @Test
        void keyOperator_canRotateKek() {
            ServiceIdentity operator = machine("operator-svc", EncryptionRole.KEY_OPERATOR);
            assertGranted(operator, EncryptionPermission.ROTATE_KEK);
        }

        @Test
        void keyOperator_canDeleteUserDek() {
            ServiceIdentity operator = machine("operator-svc", EncryptionRole.KEY_OPERATOR);
            assertGranted(operator, EncryptionPermission.DELETE_USER_DEK);
        }

        @Test
        void auditor_canViewAuditLogs() {
            ServiceIdentity auditor = machine("auditor-svc", EncryptionRole.AUDITOR);
            assertGranted(auditor, EncryptionPermission.VIEW_AUDIT_LOGS);
        }

        @Test
        void auditor_canViewKeyMetadata() {
            ServiceIdentity auditor = machine("auditor-svc", EncryptionRole.AUDITOR);
            assertGranted(auditor, EncryptionPermission.VIEW_KEY_METADATA);
        }

        @Test
        void developer_canEncryptData() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            assertGranted(dev, EncryptionPermission.ENCRYPT_DATA);
        }

        @Test
        void developer_canDecryptData() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            assertGranted(dev, EncryptionPermission.DECRYPT_DATA);
        }

        @Test
        void developer_canGenerateBlindIndex() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            assertGranted(dev, EncryptionPermission.GENERATE_BLIND_INDEX);
        }
    }

    // =========================================================================
    // Unauthorized access denial tests
    // =========================================================================

    @Nested
    class UnauthorizedAccessTests {

        @Test
        void developer_cannotRotateDek() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            assertDenied(dev, EncryptionPermission.ROTATE_DEK);
        }

        @Test
        void developer_cannotRotateKek() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            assertDenied(dev, EncryptionPermission.ROTATE_KEK);
        }

        @Test
        void developer_cannotConfigureKmsPolicy() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            assertDenied(dev, EncryptionPermission.CONFIGURE_KMS_POLICY);
        }

        @Test
        void auditor_cannotEncryptData() {
            ServiceIdentity auditor = machine("auditor-svc", EncryptionRole.AUDITOR);
            assertDenied(auditor, EncryptionPermission.ENCRYPT_DATA);
        }

        @Test
        void auditor_cannotRotateDek() {
            ServiceIdentity auditor = machine("auditor-svc", EncryptionRole.AUDITOR);
            assertDenied(auditor, EncryptionPermission.ROTATE_DEK);
        }

        @Test
        void keyOperator_cannotConfigureKmsPolicy() {
            ServiceIdentity operator = machine("operator-svc", EncryptionRole.KEY_OPERATOR);
            assertDenied(operator, EncryptionPermission.CONFIGURE_KMS_POLICY);
        }

        @Test
        void cryptoAdmin_cannotRotateDek() {
            ServiceIdentity admin = machine("admin-svc", EncryptionRole.CRYPTO_ADMIN);
            assertDenied(admin, EncryptionPermission.ROTATE_DEK);
        }

        @Test
        void cryptoAdmin_cannotRotateKek() {
            ServiceIdentity admin = machine("admin-svc", EncryptionRole.CRYPTO_ADMIN);
            assertDenied(admin, EncryptionPermission.ROTATE_KEK);
        }

        @Test
        void deniedAccess_isLoggedAsSecurityEvent() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            controller.checkAccess(dev, EncryptionPermission.ROTATE_DEK, BoundedContext.PROFILE);

            assertFalse(auditLogger.getSecurityEvents().isEmpty(),
                    "Denied access should produce a security event");
            SecurityEvent event = auditLogger.getSecurityEvents().get(0);
            assertEquals("UNAUTHORIZED_KEY_ACCESS", event.getEventType());
        }

        @Test
        void noRoles_cannotDoAnything() {
            ServiceIdentity noRole = ServiceIdentity.machine("no-role-svc", Set.of());
            assertDenied(noRole, EncryptionPermission.ENCRYPT_DATA);
            assertDenied(noRole, EncryptionPermission.ROTATE_DEK);
            assertDenied(noRole, EncryptionPermission.VIEW_AUDIT_LOGS);
        }
    }

    // =========================================================================
    // Human identity rejection
    // =========================================================================

    @Nested
    class HumanIdentityTests {

        @Test
        void humanIdentity_isAlwaysRejected_forEncrypt() {
            ServiceIdentity human = ServiceIdentity.human("alice");
            Result<Unit, AccessDeniedError> result =
                    controller.checkAccess(human, EncryptionPermission.ENCRYPT_DATA, BoundedContext.PROFILE);
            assertTrue(result.isFailure());
            assertEquals("HUMAN_ACCESS_DENIED", result.getError().get().getCode());
        }

        @Test
        void humanIdentity_isAlwaysRejected_forKeyRotation() {
            ServiceIdentity human = ServiceIdentity.human("bob");
            Result<Unit, AccessDeniedError> result =
                    controller.checkAccess(human, EncryptionPermission.ROTATE_DEK, BoundedContext.CONSENT);
            assertTrue(result.isFailure());
            assertEquals("HUMAN_ACCESS_DENIED", result.getError().get().getCode());
        }

        @Test
        void humanIdentity_rejectionIsLogged() {
            ServiceIdentity human = ServiceIdentity.human("charlie");
            controller.checkAccess(human, EncryptionPermission.VIEW_KEY_METADATA, BoundedContext.PROFILE);

            assertFalse(auditLogger.getSecurityEvents().isEmpty());
            SecurityEvent event = auditLogger.getSecurityEvents().get(0);
            assertEquals("UNAUTHORIZED_KEY_ACCESS", event.getEventType());
        }
    }

    // =========================================================================
    // Separation of duties tests
    // =========================================================================

    @Nested
    class SeparationOfDutiesTests {

        @Test
        void cryptoAdmin_violatesSoD_forRotateDek() {
            ServiceIdentity admin = machine("admin-svc", EncryptionRole.CRYPTO_ADMIN);
            assertFalse(controller.validateSeparationOfDuties(admin, EncryptionPermission.ROTATE_DEK));
        }

        @Test
        void cryptoAdmin_violatesSoD_forRotateKek() {
            ServiceIdentity admin = machine("admin-svc", EncryptionRole.CRYPTO_ADMIN);
            assertFalse(controller.validateSeparationOfDuties(admin, EncryptionPermission.ROTATE_KEK));
        }

        @Test
        void keyOperator_violatesSoD_forConfigureKmsPolicy() {
            ServiceIdentity operator = machine("operator-svc", EncryptionRole.KEY_OPERATOR);
            assertFalse(controller.validateSeparationOfDuties(operator,
                    EncryptionPermission.CONFIGURE_KMS_POLICY));
        }

        @Test
        void auditor_violatesSoD_forEncryptData() {
            ServiceIdentity auditor = machine("auditor-svc", EncryptionRole.AUDITOR);
            assertFalse(controller.validateSeparationOfDuties(auditor, EncryptionPermission.ENCRYPT_DATA));
        }

        @Test
        void auditor_violatesSoD_forRotateDek() {
            ServiceIdentity auditor = machine("auditor-svc", EncryptionRole.AUDITOR);
            assertFalse(controller.validateSeparationOfDuties(auditor, EncryptionPermission.ROTATE_DEK));
        }

        @Test
        void developer_doesNotViolateSoD_forEncryptData() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            assertTrue(controller.validateSeparationOfDuties(dev, EncryptionPermission.ENCRYPT_DATA));
        }

        @Test
        void keyOperator_doesNotViolateSoD_forRotateDek() {
            ServiceIdentity operator = machine("operator-svc", EncryptionRole.KEY_OPERATOR);
            assertTrue(controller.validateSeparationOfDuties(operator, EncryptionPermission.ROTATE_DEK));
        }
    }

    // =========================================================================
    // Break-glass dual authorization
    // =========================================================================

    @Nested
    class BreakGlassTests {

        @Test
        void breakGlass_requiresTwoDistinctApprovers() {
            ServiceIdentity op1 = machine("operator-1", EncryptionRole.KEY_OPERATOR);
            ServiceIdentity op2 = machine("operator-2", EncryptionRole.KEY_OPERATOR);

            Result<Unit, AccessDeniedError> first =
                    controller.initiateBreakGlass("emergency-kek-rotation", op1);
            assertTrue(first.isSuccess(), "First approval should succeed");
            assertTrue(controller.isBreakGlassPending("emergency-kek-rotation"));

            Result<Unit, AccessDeniedError> second =
                    controller.approveBreakGlass("emergency-kek-rotation", op2);
            assertTrue(second.isSuccess(), "Second approval from different approver should succeed");
            assertFalse(controller.isBreakGlassPending("emergency-kek-rotation"),
                    "Break-glass should be cleared after dual authorization");
        }

        @Test
        void breakGlass_rejectsSameApproverTwice() {
            ServiceIdentity op = machine("operator-1", EncryptionRole.KEY_OPERATOR);

            controller.initiateBreakGlass("emergency-op", op);
            Result<Unit, AccessDeniedError> second =
                    controller.approveBreakGlass("emergency-op", op);

            assertTrue(second.isFailure(),
                    "Same approver cannot provide dual authorization");
        }

        @Test
        void breakGlass_rejectsHumanApprover() {
            ServiceIdentity human = ServiceIdentity.human("alice");
            Result<Unit, AccessDeniedError> result =
                    controller.initiateBreakGlass("emergency-op", human);
            assertTrue(result.isFailure());
            assertEquals("HUMAN_ACCESS_DENIED", result.getError().get().getCode());
        }

        @Test
        void breakGlass_rejectsApproverWithoutKeyOperatorRole() {
            ServiceIdentity dev = machine("profile-svc", EncryptionRole.DEVELOPER);
            Result<Unit, AccessDeniedError> result =
                    controller.initiateBreakGlass("emergency-op", dev);
            assertTrue(result.isFailure());
        }

        @Test
        void breakGlass_logsSecurityEvents() {
            ServiceIdentity op1 = machine("operator-1", EncryptionRole.KEY_OPERATOR);
            ServiceIdentity op2 = machine("operator-2", EncryptionRole.KEY_OPERATOR);

            controller.initiateBreakGlass("logged-op", op1);
            controller.approveBreakGlass("logged-op", op2);

            List<SecurityEvent> events = auditLogger.getSecurityEvents();
            assertTrue(events.stream().anyMatch(e -> "BREAK_GLASS_INITIATED".equals(e.getEventType())));
            assertTrue(events.stream().anyMatch(e -> "BREAK_GLASS_AUTHORIZED".equals(e.getEventType())));
        }

        @Test
        void breakGlass_approveWithoutInitiate_fails() {
            ServiceIdentity op = machine("operator-1", EncryptionRole.KEY_OPERATOR);
            Result<Unit, AccessDeniedError> result =
                    controller.approveBreakGlass("nonexistent-op", op);
            assertTrue(result.isFailure());
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static ServiceIdentity machine(String name, EncryptionRole role) {
        return ServiceIdentity.machine(name, Set.of(role));
    }

    private void assertGranted(ServiceIdentity identity, EncryptionPermission permission) {
        Result<Unit, AccessDeniedError> result =
                controller.checkAccess(identity, permission, BoundedContext.PROFILE);
        assertTrue(result.isSuccess(),
                identity.getServiceName() + " should have " + permission
                        + " but got: " + result.getError().map(AccessDeniedError::getMessage).orElse(""));
    }

    private void assertDenied(ServiceIdentity identity, EncryptionPermission permission) {
        Result<Unit, AccessDeniedError> result =
                controller.checkAccess(identity, permission, BoundedContext.PROFILE);
        assertTrue(result.isFailure(),
                identity.getServiceName() + " should NOT have " + permission);
    }

    // =========================================================================
    // Minimal IAuditLogger stub
    // =========================================================================

    static class CapturingAuditLogger implements IAuditLogger {

        private final List<SecurityEvent> securityEvents = new ArrayList<>();

        public List<SecurityEvent> getSecurityEvents() {
            return Collections.unmodifiableList(securityEvents);
        }

        @Override
        public Result<Void, AuditError> logEncryption(EncryptionEvent event) { return ok(); }

        @Override
        public Result<Void, AuditError> logDecryption(DecryptionEvent event) { return ok(); }

        @Override
        public Result<Void, AuditError> logKeyRotation(KeyRotationEvent event) { return ok(); }

        @Override
        public Result<Void, AuditError> logSecurityEvent(SecurityEvent event) {
            securityEvents.add(event);
            return ok();
        }

        @Override
        public Result<Void, AuditError> logKeyAccess(KeyAccessEvent event) { return ok(); }

        @Override
        public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) { return ok(); }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private static Result<Void, AuditError> ok() {
            return (Result<Void, AuditError>) (Result) Result.success(Unit.unit());
        }
    }
}
