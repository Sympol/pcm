package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.AccessDeniedError;
import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.EncryptionPermission;
import dev.vibeafrika.pcm.domain.encryption.IAuditLogger;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.SecurityEvent;
import dev.vibeafrika.pcm.domain.encryption.ServiceIdentity;
import dev.vibeafrika.pcm.domain.encryption.Unit;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Infrastructure service that enforces cloud root account protection controls.
 *
 * <p>Implements :
 * <ul>
 *   <li>Hardware MFA requirement for root account access</li>
 *   <li>Real-time alerting on any root account usage</li>
 *   <li>SCP enforcement restricting root KMS access</li>
 *   <li>Break-glass dual authorization via {@link RbacAccessController}</li>
 *   <li>Emergency access procedure documentation</li>
 *   <li>Weekly access log review</li>
 * </ul>
 *
 * <p>This is a concrete infrastructure class – it does not define a domain port.
 * It composes with {@link RbacAccessController} for dual-authorization break-glass
 * and with {@link IAuditLogger} for all alerting and audit logging.
 */
public class RootAccountProtectionService {

    /** Logical identity used when logging system-level root account events. */
    private static final String ROOT_ACCOUNT_SYSTEM_IDENTITY = "root-account-protection-service";

    /**
     * KMS operation prefixes that are restricted by SCP for the root account.
     * Root account must not perform routine KMS operations.
     */
    private static final java.util.Set<String> SCP_RESTRICTED_KMS_OPERATIONS = java.util.Set.of(
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:DescribeKey",
            "kms:ListKeys",
            "kms:CreateKey",
            "kms:ScheduleKeyDeletion",
            "kms:EnableKeyRotation",
            "kms:DisableKeyRotation"
    );

    private final IAuditLogger auditLogger;
    private final RbacAccessController rbacAccessController;

    /**
     * Whether hardware MFA is configured for the root account.
     * When {@code false}, root account access is denied.
     */
    private final boolean hardwareMfaConfigured;

    /**
     * Creates a {@code RootAccountProtectionService}.
     *
     * @param auditLogger            audit logger for all security events
     * @param rbacAccessController   RBAC controller used for break-glass dual authorization
     * @param hardwareMfaConfigured  {@code true} when hardware MFA is provisioned for root
     */
    public RootAccountProtectionService(IAuditLogger auditLogger,
                                        RbacAccessController rbacAccessController,
                                        boolean hardwareMfaConfigured) {
        this.auditLogger = Objects.requireNonNull(auditLogger, "AuditLogger cannot be null");
        this.rbacAccessController = Objects.requireNonNull(rbacAccessController,
                "RbacAccessController cannot be null");
        this.hardwareMfaConfigured = hardwareMfaConfigured;
    }

    // -------------------------------------------------------------------------
    // Root account access recording
    // -------------------------------------------------------------------------

    /**
     * Records a root account access attempt, generates a CRITICAL alert, and
     * enforces the hardware MFA requirement.
     *
     * <p>Always generates a {@code ROOT_ACCOUNT_ACCESS} security event regardless
     * of MFA state.
     *
     * @param justification      reason provided for the access
     * @param requestorIdentity  identity of the person/system requesting access
     * @return success when MFA is configured; failure with {@link AccessDeniedError} otherwise
     */
    public Result<Unit, AccessDeniedError> recordRootAccountAccess(String justification,
                                                                    String requestorIdentity) {
        Objects.requireNonNull(justification, "Justification cannot be null");
        Objects.requireNonNull(requestorIdentity, "Requestor identity cannot be null");

        // Always alert on root account access (Requirement 34.2)
        generateRootAccessAlert(requestorIdentity, justification);

        if (!hardwareMfaConfigured) {
            AccessDeniedError error = AccessDeniedError.of(requestorIdentity,
                    EncryptionPermission.CONFIGURE_KMS_POLICY);
            return Result.failure(error);
        }

        return Result.success(Unit.unit());
    }

    // -------------------------------------------------------------------------
    // Break-glass dual authorization 
    // -------------------------------------------------------------------------

    /**
     * Initiates a break-glass emergency operation, recording the first approval.
     * Delegates dual-authorization logic to {@link RbacAccessController} and logs
     * a CRITICAL security event.
     *
     * @param operationKey unique key identifying the break-glass operation
     * @param approver     first approving service identity
     * @return success when the first approval is recorded; failure otherwise
     */
    public Result<Unit, AccessDeniedError> initiateBreakGlass(String operationKey,
                                                               ServiceIdentity approver) {
        Objects.requireNonNull(operationKey, "Operation key cannot be null");
        Objects.requireNonNull(approver, "Approver cannot be null");

        Result<Unit, AccessDeniedError> result =
                rbacAccessController.initiateBreakGlass(operationKey, approver);

        // Log regardless of outcome so every attempt is audited
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity(ROOT_ACCOUNT_SYSTEM_IDENTITY)
                .userContext(approver.getServiceName())
                .eventType("ROOT_BREAK_GLASS_INITIATED")
                .severity("CRITICAL")
                .description("Root account break-glass initiated | operation=" + operationKey
                        + " | approver=" + approver.getServiceName()
                        + " | success=" + result.isSuccess())
                .metadata(Map.of(
                        "operationKey", operationKey,
                        "approverIdentity", approver.getServiceName(),
                        "success", result.isSuccess()
                ))
                .build();
        auditLogger.logSecurityEvent(event);

        return result;
    }

    /**
     * Approves a pending break-glass operation with a second, distinct approver,
     * completing dual authorization. Logs a CRITICAL security event.
     *
     * @param operationKey unique key identifying the break-glass operation
     * @param approver     second approving service identity (must differ from first)
     * @return success when dual authorization is complete; failure otherwise
     */
    public Result<Unit, AccessDeniedError> approveBreakGlass(String operationKey,
                                                              ServiceIdentity approver) {
        Objects.requireNonNull(operationKey, "Operation key cannot be null");
        Objects.requireNonNull(approver, "Approver cannot be null");

        Result<Unit, AccessDeniedError> result =
                rbacAccessController.approveBreakGlass(operationKey, approver);

        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity(ROOT_ACCOUNT_SYSTEM_IDENTITY)
                .userContext(approver.getServiceName())
                .eventType("ROOT_BREAK_GLASS_APPROVED")
                .severity("CRITICAL")
                .description("Root account break-glass approval | operation=" + operationKey
                        + " | approver=" + approver.getServiceName()
                        + " | authorized=" + result.isSuccess())
                .metadata(Map.of(
                        "operationKey", operationKey,
                        "approverIdentity", approver.getServiceName(),
                        "authorized", result.isSuccess()
                ))
                .build();
        auditLogger.logSecurityEvent(event);

        return result;
    }

    // -------------------------------------------------------------------------
    // Routine KMS operation prohibition 
    // -------------------------------------------------------------------------

    /**
     * Returns {@code false} for the root account identity, prohibiting it from
     * performing routine KMS operations.
     *
     * @param identity the service identity to check
     * @return {@code false} when the identity is the root account; {@code true} otherwise
     */
    public boolean isRoutineKmsOperationAllowed(ServiceIdentity identity) {
        Objects.requireNonNull(identity, "ServiceIdentity cannot be null");
        return !isRootAccount(identity);
    }

    // -------------------------------------------------------------------------
    // Root access alerting 
    // -------------------------------------------------------------------------

    /**
     * Creates and logs a CRITICAL {@code ROOT_ACCOUNT_ACCESS} security event.
     *
     * @param accessorIdentity identity of the accessor
     * @param justification    stated reason for the access
     */
    public void generateRootAccessAlert(String accessorIdentity, String justification) {
        Objects.requireNonNull(accessorIdentity, "Accessor identity cannot be null");
        Objects.requireNonNull(justification, "Justification cannot be null");

        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity(ROOT_ACCOUNT_SYSTEM_IDENTITY)
                .userContext(accessorIdentity)
                .eventType("ROOT_ACCOUNT_ACCESS")
                .severity("CRITICAL")
                .description("Root account access detected | accessor=" + accessorIdentity
                        + " | justification=" + justification)
                .metadata(Map.of(
                        "accessorIdentity", accessorIdentity,
                        "justification", justification,
                        "hardwareMfaConfigured", hardwareMfaConfigured
                ))
                .build();
        auditLogger.logSecurityEvent(event);
    }

    // -------------------------------------------------------------------------
    // SCP compliance validation
    // -------------------------------------------------------------------------

    /**
     * Validates whether an operation is permitted under the Service Control Policy.
     *
     * <p>Returns {@code false} for KMS operations that are restricted by SCP for
     * the root account .
     *
     * @param operation the operation name to check (e.g. {@code "kms:Encrypt"})
     * @return {@code false} when the operation is SCP-restricted; {@code true} otherwise
     */
    public boolean validateScpCompliance(String operation) {
        Objects.requireNonNull(operation, "Operation cannot be null");
        return !SCP_RESTRICTED_KMS_OPERATIONS.contains(operation);
    }

    // -------------------------------------------------------------------------
    // Weekly access log review
    // -------------------------------------------------------------------------

    /**
     * Logs an audit event recording that the weekly root account access log review
     * was performed.
     *
     * @param reviewerIdentity identity of the reviewer performing the weekly review
     */
    public void reviewAccessLogs(String reviewerIdentity) {
        Objects.requireNonNull(reviewerIdentity, "Reviewer identity cannot be null");

        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE)
                .serviceIdentity(ROOT_ACCOUNT_SYSTEM_IDENTITY)
                .userContext(reviewerIdentity)
                .eventType("ROOT_ACCESS_LOG_REVIEW")
                .severity("HIGH")
                .description("Weekly root account access log review performed | reviewer="
                        + reviewerIdentity)
                .metadata(Map.of(
                        "reviewerIdentity", reviewerIdentity,
                        "reviewType", "WEEKLY"
                ))
                .build();
        auditLogger.logSecurityEvent(event);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Heuristic: a service identity is considered the root account when its name
     * contains "root" (case-insensitive).
     */
    private boolean isRootAccount(ServiceIdentity identity) {
        return identity.getServiceName().toLowerCase().contains("root");
    }
}
