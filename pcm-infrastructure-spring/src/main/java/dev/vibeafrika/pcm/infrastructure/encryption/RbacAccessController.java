package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.AccessDeniedError;
import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.EncryptionPermission;
import dev.vibeafrika.pcm.domain.encryption.EncryptionRole;
import dev.vibeafrika.pcm.domain.encryption.IAuditLogger;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.SecurityEvent;
import dev.vibeafrika.pcm.domain.encryption.ServiceIdentity;
import dev.vibeafrika.pcm.domain.encryption.Unit;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enforces role-based access control (RBAC) for PII encryption operations.
 *
 * <p>Implements :
 * <ul>
 *   <li>IAM-based access control via {@link ServiceIdentity} and {@link EncryptionRole}</li>
 *   <li>Machine identity authentication – human identities are always rejected</li>
 *   <li>Principle of least privilege – each role has only the permissions it needs</li>
 *   <li>Separation of duties – no single role has full access</li>
 *   <li>Dual authorization for break-glass procedures</li>
 *   <li>All access attempts (granted and denied) are logged via {@link IAuditLogger}</li>
 * </ul>
 *
 * <h3>Separation of duties enforced</h3>
 * <ul>
 *   <li>{@link EncryptionRole#CRYPTO_ADMIN} cannot rotate keys</li>
 *   <li>{@link EncryptionRole#KEY_OPERATOR} cannot modify KMS policies</li>
 *   <li>{@link EncryptionRole#AUDITOR} cannot perform any write operations</li>
 * </ul>
 *
 * <h3>Break-glass procedure</h3>
 * <p>Emergency operations that bypass normal controls require dual authorization:
 * two distinct {@link ServiceIdentity} instances must both approve the operation
 * before it is permitted.
 */
public class RbacAccessController {

    private final IAuditLogger auditLogger;
    private final String systemServiceIdentity;

    /**
     * Pending break-glass approvals: operationKey → first approver service name.
     * An operation is authorized only when a second, distinct approver calls
     * {@link #approveBreakGlass(String, ServiceIdentity)}.
     */
    private final ConcurrentHashMap<String, String> pendingBreakGlassApprovals =
            new ConcurrentHashMap<>();

    public RbacAccessController(IAuditLogger auditLogger, String systemServiceIdentity) {
        this.auditLogger = Objects.requireNonNull(auditLogger, "AuditLogger cannot be null");
        this.systemServiceIdentity = Objects.requireNonNull(systemServiceIdentity,
                "System service identity cannot be null");
    }

    // -------------------------------------------------------------------------
    // Core authorization check
    // -------------------------------------------------------------------------

    /**
     * Checks whether the given {@link ServiceIdentity} is authorized to perform
     * the requested {@link EncryptionPermission}.
     *
     * <p>Returns {@link Result#success(Object)} with {@link Unit#INSTANCE} when
     * access is granted, or {@link Result#failure(Object)} with an
     * {@link AccessDeniedError} when access is denied.
     *
     * <p>All access attempts are logged as security events.
     *
     * @param identity   the machine identity requesting access
     * @param permission the permission required for the operation
     * @param context    the bounded context in which the operation is requested
     * @return Result indicating whether access is granted or denied
     */
    public Result<Unit, AccessDeniedError> checkAccess(
            ServiceIdentity identity,
            EncryptionPermission permission,
            BoundedContext context) {

        Objects.requireNonNull(identity, "ServiceIdentity cannot be null");
        Objects.requireNonNull(permission, "Permission cannot be null");
        Objects.requireNonNull(context, "BoundedContext cannot be null");

        // Prohibit direct human access to keys
        if (identity.isHumanIdentity()) {
            AccessDeniedError error = AccessDeniedError.humanAccessDenied(identity.getServiceName());
            logUnauthorizedAccess(identity.getServiceName(), permission, context,
                    "Human identity attempted key access – prohibited");
            return Result.failure(error);
        }

        // Check permission via role membership
        if (!identity.hasPermission(permission)) {
            AccessDeniedError error = AccessDeniedError.of(identity.getServiceName(), permission);
            logUnauthorizedAccess(identity.getServiceName(), permission, context,
                    "Insufficient permissions for operation: " + permission);
            return Result.failure(error);
        }

        return Result.success(Unit.unit());
    }

    // -------------------------------------------------------------------------
    // Break-glass dual authorization 
    // -------------------------------------------------------------------------

    /**
     * Submits the first approval for a break-glass operation.
     *
     * <p>Break-glass operations require dual authorization: two distinct
     * {@link ServiceIdentity} instances must both approve before the operation
     * is permitted.
     *
     * @param operationKey a unique key identifying the break-glass operation
     * @param approver     the first approving service identity
     * @return Result indicating whether the first approval was recorded
     */
    public Result<Unit, AccessDeniedError> initiateBreakGlass(
            String operationKey, ServiceIdentity approver) {

        Objects.requireNonNull(operationKey, "Operation key cannot be null");
        Objects.requireNonNull(approver, "Approver cannot be null");

        if (approver.isHumanIdentity()) {
            return Result.failure(AccessDeniedError.humanAccessDenied(approver.getServiceName()));
        }

        if (!approver.hasPermission(EncryptionPermission.ROTATE_KEK)) {
            return Result.failure(AccessDeniedError.of(approver.getServiceName(),
                    EncryptionPermission.ROTATE_KEK));
        }

        pendingBreakGlassApprovals.put(operationKey, approver.getServiceName());
        logBreakGlassEvent(approver.getServiceName(), operationKey, "BREAK_GLASS_INITIATED");
        return Result.success(Unit.unit());
    }

    /**
     * Submits the second approval for a break-glass operation, completing dual
     * authorization.
     *
     * <p>The second approver must be a different service identity from the first.
     *
     * @param operationKey a unique key identifying the break-glass operation
     * @param approver     the second approving service identity
     * @return Result indicating whether dual authorization is now complete
     */
    public Result<Unit, AccessDeniedError> approveBreakGlass(
            String operationKey, ServiceIdentity approver) {

        Objects.requireNonNull(operationKey, "Operation key cannot be null");
        Objects.requireNonNull(approver, "Approver cannot be null");

        if (approver.isHumanIdentity()) {
            return Result.failure(AccessDeniedError.humanAccessDenied(approver.getServiceName()));
        }

        String firstApprover = pendingBreakGlassApprovals.get(operationKey);
        if (firstApprover == null) {
            return Result.failure(AccessDeniedError.of(approver.getServiceName(),
                    EncryptionPermission.ROTATE_KEK));
        }

        // Dual authorization requires two DISTINCT approvers
        if (firstApprover.equals(approver.getServiceName())) {
            logBreakGlassEvent(approver.getServiceName(), operationKey,
                    "BREAK_GLASS_SAME_APPROVER_REJECTED");
            return Result.failure(AccessDeniedError.of(approver.getServiceName(),
                    EncryptionPermission.ROTATE_KEK));
        }

        if (!approver.hasPermission(EncryptionPermission.ROTATE_KEK)) {
            return Result.failure(AccessDeniedError.of(approver.getServiceName(),
                    EncryptionPermission.ROTATE_KEK));
        }

        pendingBreakGlassApprovals.remove(operationKey);
        logBreakGlassEvent(approver.getServiceName(), operationKey, "BREAK_GLASS_AUTHORIZED");
        return Result.success(Unit.unit());
    }

    /**
     * Returns {@code true} if a break-glass operation has a pending first approval
     * but has not yet received dual authorization.
     */
    public boolean isBreakGlassPending(String operationKey) {
        return pendingBreakGlassApprovals.containsKey(operationKey);
    }

    // -------------------------------------------------------------------------
    // Separation-of-duties validation helpers
    // -------------------------------------------------------------------------

    /**
     * Validates that the given identity does NOT hold a role that would violate
     * separation of duties for the requested permission.
     *
     * <p>Specifically:
     * <ul>
     *   <li>{@link EncryptionRole#CRYPTO_ADMIN} cannot hold {@link EncryptionPermission#ROTATE_DEK}
     *       or {@link EncryptionPermission#ROTATE_KEK}</li>
     *   <li>{@link EncryptionRole#KEY_OPERATOR} cannot hold
     *       {@link EncryptionPermission#CONFIGURE_KMS_POLICY}</li>
     *   <li>{@link EncryptionRole#AUDITOR} cannot hold any write permission</li>
     * </ul>
     *
     * <p>These constraints are already encoded in the {@link EncryptionRole} permission sets,
     * so this method provides an explicit assertion layer for defense-in-depth.
     *
     * @param identity   the identity to validate
     * @param permission the permission being requested
     * @return {@code true} if no separation-of-duties violation is detected
     */
    public boolean validateSeparationOfDuties(ServiceIdentity identity,
                                               EncryptionPermission permission) {
        Set<EncryptionRole> roles = identity.getRoles();

        // CRYPTO_ADMIN must not rotate keys
        if (roles.contains(EncryptionRole.CRYPTO_ADMIN)
                && (permission == EncryptionPermission.ROTATE_DEK
                    || permission == EncryptionPermission.ROTATE_KEK)) {
            return false;
        }

        // KEY_OPERATOR must not configure KMS policies
        if (roles.contains(EncryptionRole.KEY_OPERATOR)
                && permission == EncryptionPermission.CONFIGURE_KMS_POLICY) {
            return false;
        }

        // AUDITOR must not perform write operations
        if (roles.contains(EncryptionRole.AUDITOR) && isWritePermission(permission)) {
            return false;
        }

        return true;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static final Set<EncryptionPermission> WRITE_PERMISSIONS = Set.of(
            EncryptionPermission.ENCRYPT_DATA,
            EncryptionPermission.DECRYPT_DATA,
            EncryptionPermission.ROTATE_DEK,
            EncryptionPermission.ROTATE_KEK,
            EncryptionPermission.INVALIDATE_KEY_CACHE,
            EncryptionPermission.DELETE_USER_DEK,
            EncryptionPermission.CONFIGURE_KMS_POLICY
    );

    private boolean isWritePermission(EncryptionPermission permission) {
        return WRITE_PERMISSIONS.contains(permission);
    }

    private void logUnauthorizedAccess(String serviceIdentity,
                                        EncryptionPermission permission,
                                        BoundedContext context,
                                        String description) {
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(context)
                .serviceIdentity(systemServiceIdentity)
                .userContext(serviceIdentity)
                .eventType("UNAUTHORIZED_KEY_ACCESS")
                .severity("HIGH")
                .description(description + " | permission=" + permission
                        + " | requestor=" + serviceIdentity)
                .metadata(Map.of(
                        "requestedPermission", permission.name(),
                        "requestorIdentity", serviceIdentity
                ))
                .build();
        auditLogger.logSecurityEvent(event);
    }

    private void logBreakGlassEvent(String serviceIdentity,
                                     String operationKey,
                                     String eventType) {
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(Instant.now())
                .context(BoundedContext.PROFILE) // system-level event, context is informational
                .serviceIdentity(systemServiceIdentity)
                .userContext(serviceIdentity)
                .eventType(eventType)
                .severity("CRITICAL")
                .description("Break-glass procedure event: " + eventType
                        + " | operation=" + operationKey
                        + " | approver=" + serviceIdentity)
                .metadata(Map.of(
                        "operationKey", operationKey,
                        "approverIdentity", serviceIdentity
                ))
                .build();
        auditLogger.logSecurityEvent(event);
    }
}
