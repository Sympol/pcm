package dev.vibeafrika.pcm.infrastructure.spring.encryption.network;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for network security components.
 *
 * <p>Tests cover :
 * <ul>
 *   <li>mTLS configuration is properly set up</li>
 *   <li>Connections from unauthorized IPs are rejected</li>
 *   <li>Private subnet access enforcement</li>
 *   <li>KMS connection attempts are logged</li>
 * </ul>
 */
class NetworkSecurityIntegrationTest {

    // =========================================================================
    // mTLS Configuration Tests 
    // =========================================================================

    @Nested
    @DisplayName("mTLS Configuration")
    class MtlsConfigurationTests {

        @Test
        @DisplayName("mTLS disabled returns default SSLContext without throwing")
        void mtlsDisabled_returnsDefaultSslContext() throws Exception {
            MtlsConfiguration.MtlsProperties props = new MtlsConfiguration.MtlsProperties();
            props.setEnabled(false);

            MtlsConfiguration config = new MtlsConfiguration(props);
            SSLContext sslContext = config.kmsSslContext();

            assertThat(sslContext).isNotNull();
            assertThat(sslContext.getProtocol()).isNotEmpty();
        }

        @Test
        @DisplayName("mTLS enabled with missing keystore throws IllegalStateException")
        void mtlsEnabled_missingKeystore_throwsIllegalStateException() {
            MtlsConfiguration.MtlsProperties props = new MtlsConfiguration.MtlsProperties();
            props.setEnabled(true);
            props.setKeystorePath("/nonexistent/client.p12");
            props.setKeystorePassword("changeit".toCharArray());
            props.setTruststorePath("/nonexistent/truststore.jks");
            props.setTruststorePassword("changeit".toCharArray());

            MtlsConfiguration config = new MtlsConfiguration(props);

            assertThatThrownBy(config::kmsSslContext)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Failed to configure mTLS SSLContext");
        }

        @Test
        @DisplayName("mTLS properties default to TLSv1.3 protocol")
        void mtlsProperties_defaultTlsProtocol_isTlsV13() {
            MtlsConfiguration.MtlsProperties props = new MtlsConfiguration.MtlsProperties();
            assertThat(props.getTlsProtocol()).isEqualTo("TLSv1.3");
        }

        @Test
        @DisplayName("mTLS properties default to PKCS12 keystore type")
        void mtlsProperties_defaultKeystoreType_isPkcs12() {
            MtlsConfiguration.MtlsProperties props = new MtlsConfiguration.MtlsProperties();
            assertThat(props.getKeystoreType()).isEqualTo("PKCS12");
        }

        @Test
        @DisplayName("mTLS is disabled by default (safe default for tests)")
        void mtlsProperties_defaultEnabled_isFalse() {
            MtlsConfiguration.MtlsProperties props = new MtlsConfiguration.MtlsProperties();
            assertThat(props.isEnabled()).isFalse();
        }
    }

    // =========================================================================
    // Private Subnet Access Tests 
    // =========================================================================

    @Nested
    @DisplayName("Private Subnet Validation")
    class PrivateSubnetTests {

        @Test
        @DisplayName("10.x.x.x addresses are recognized as private")
        void class_A_privateAddresses_areRecognized() {
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("10.0.0.1")).isTrue();
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("10.255.255.255")).isTrue();
        }

        @Test
        @DisplayName("172.16-31.x.x addresses are recognized as private")
        void class_B_privateAddresses_areRecognized() {
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("172.16.0.1")).isTrue();
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("172.31.255.255")).isTrue();
        }

        @Test
        @DisplayName("192.168.x.x addresses are recognized as private")
        void class_C_privateAddresses_areRecognized() {
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("192.168.0.1")).isTrue();
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("192.168.255.255")).isTrue();
        }

        @Test
        @DisplayName("Loopback 127.x.x.x is recognized as private (for local/test environments)")
        void loopback_isRecognizedAsPrivate() {
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("127.0.0.1")).isTrue();
        }

        @Test
        @DisplayName("Public IP addresses are not recognized as private")
        void publicAddresses_areNotPrivate() {
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("8.8.8.8")).isFalse();
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("52.0.0.1")).isFalse();
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("203.0.113.1")).isFalse();
        }

        @Test
        @DisplayName("Null or blank IP returns false")
        void nullOrBlankIp_returnsFalse() {
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress(null)).isFalse();
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("")).isFalse();
            assertThat(NetworkSecurityConfiguration.isPrivateSubnetAddress("   ")).isFalse();
        }

        @Test
        @DisplayName("KMS endpoint validator skips validation when private-subnet-only is false")
        void endpointValidator_privateSubnetOnlyFalse_doesNotValidate() {
            // Should not throw even with a public-looking endpoint
            NetworkSecurityConfiguration.KmsEndpointValidator validator =
                    new NetworkSecurityConfiguration.KmsEndpointValidator(
                            "https://kms.amazonaws.com", false);
            // No exception = pass
        }
    }

    // =========================================================================
    // Firewall / IP Allowlist Tests 
    // =========================================================================

    @Nested
    @DisplayName("KMS Connection Interceptor – IP Allowlist")
    class KmsConnectionInterceptorTests {

        private KmsConnectionInterceptor interceptor;
        private CapturingAuditLogger capturingLogger;

        @BeforeEach
        void setUp() {
            capturingLogger = new CapturingAuditLogger();
            interceptor = new KmsConnectionInterceptor(
                    List.of("10.0.1.5", "10.0.1.6"),
                    true /* privateSubnetOnly */);
            interceptor.setAuditLogger(capturingLogger);
        }

        @Test
        @DisplayName("Authorized IP in allowlist is permitted")
        void authorizedIp_isPermitted() {
            boolean allowed = interceptor.checkConnection("10.0.1.5", "https://kms.internal");
            assertThat(allowed).isTrue();
        }

        @Test
        @DisplayName("Second authorized IP in allowlist is permitted")
        void secondAuthorizedIp_isPermitted() {
            boolean allowed = interceptor.checkConnection("10.0.1.6", "https://kms.internal");
            assertThat(allowed).isTrue();
        }

        @Test
        @DisplayName("IP not in allowlist is rejected")
        void unauthorizedIp_isRejected() {
            boolean allowed = interceptor.checkConnection("10.0.1.99", "https://kms.internal");
            assertThat(allowed).isFalse();
        }

        @Test
        @DisplayName("Public IP is rejected even if it were in the allowlist")
        void publicIp_isRejectedByPrivateSubnetCheck() {
            // Create interceptor with public IP in allowlist to test subnet check takes priority
            KmsConnectionInterceptor strictInterceptor = new KmsConnectionInterceptor(
                    List.of("8.8.8.8"), true);
            boolean allowed = strictInterceptor.checkConnection("8.8.8.8", "https://kms.internal");
            assertThat(allowed).isFalse();
        }

        @Test
        @DisplayName("Rejected connection triggers security event logging")
        void rejectedConnection_logsSecurityEvent() {
            interceptor.checkConnection("10.0.1.99", "https://kms.internal");
            assertThat(capturingLogger.getSecurityEvents()).hasSize(1);
            SecurityEvent event = capturingLogger.getSecurityEvents().get(0);
            assertThat(event.getEventType()).isEqualTo("UNAUTHORIZED_KMS_CONNECTION");
            assertThat(event.getSeverity()).isEqualTo("HIGH");
        }

        @Test
        @DisplayName("Authorized connection does not trigger security event")
        void authorizedConnection_doesNotLogSecurityEvent() {
            interceptor.checkConnection("10.0.1.5", "https://kms.internal");
            assertThat(capturingLogger.getSecurityEvents()).isEmpty();
        }

        @Test
        @DisplayName("Empty allowlist permits any private IP (no IP restriction)")
        void emptyAllowlist_permitsAnyPrivateIp() {
            KmsConnectionInterceptor openInterceptor = new KmsConnectionInterceptor(
                    List.of(), true);
            boolean allowed = openInterceptor.checkConnection("10.0.99.1", "https://kms.internal");
            assertThat(allowed).isTrue();
        }

        @Test
        @DisplayName("Null source IP throws NullPointerException")
        void nullSourceIp_throwsNpe() {
            org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class,
                    () -> interceptor.checkConnection(null, "https://kms.internal"));
        }

        @Test
        @DisplayName("Null destination throws NullPointerException")
        void nullDestination_throwsNpe() {
            org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class,
                    () -> interceptor.checkConnection("10.0.1.5", null));
        }
    }

    // =========================================================================
    // Connection Logging Tests
    // =========================================================================

    @Nested
    @DisplayName("KMS Connection Attempt Logging")
    class ConnectionLoggingTests {

        @Test
        @DisplayName("Every connection attempt is logged (authorized)")
        void authorizedAttempt_isLogged() {
            // The interceptor always logs via SLF4J; we verify no exception is thrown
            // and the method returns the correct result.
            KmsConnectionInterceptor interceptor = new KmsConnectionInterceptor(
                    List.of("10.0.1.5"), false);
            boolean result = interceptor.checkConnection("10.0.1.5", "https://kms.internal");
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Unauthorized attempt is logged as security event with correct metadata")
        void unauthorizedAttempt_securityEventContainsMetadata() {
            CapturingAuditLogger logger = new CapturingAuditLogger();
            KmsConnectionInterceptor interceptor = new KmsConnectionInterceptor(
                    List.of("10.0.1.5"), true);
            interceptor.setAuditLogger(logger);

            interceptor.checkConnection("10.0.2.99", "https://kms.internal");

            assertThat(logger.getSecurityEvents()).hasSize(1);
            SecurityEvent event = logger.getSecurityEvents().get(0);
            assertThat(event.getMetadata()).containsKey("sourceIp");
            assertThat(event.getMetadata()).containsKey("destination");
            assertThat(event.getMetadata().get("sourceIp")).isEqualTo("10.0.2.99");
        }

        @Test
        @DisplayName("Security event timestamp is set to current time")
        void securityEvent_hasTimestamp() {
            CapturingAuditLogger logger = new CapturingAuditLogger();
            KmsConnectionInterceptor interceptor = new KmsConnectionInterceptor(
                    List.of("10.0.1.5"), true);
            interceptor.setAuditLogger(logger);

            interceptor.checkConnection("10.0.2.99", "https://kms.internal");

            SecurityEvent event = logger.getSecurityEvents().get(0);
            assertThat(event.getTimestamp()).isNotNull();
        }
    }

    // =========================================================================
    // Test helpers
    // =========================================================================

    /**
     * Minimal {@link IAuditLogger} that captures security events for assertion.
     */
    static class CapturingAuditLogger implements IAuditLogger {

        private final List<SecurityEvent> securityEvents = new ArrayList<>();

        public List<SecurityEvent> getSecurityEvents() {
            return Collections.unmodifiableList(securityEvents);
        }

        @Override
        public Result<Void, AuditError> logEncryption(EncryptionEvent event) {
            return voidSuccess();
        }

        @Override
        public Result<Void, AuditError> logDecryption(DecryptionEvent event) {
            return voidSuccess();
        }

        @Override
        public Result<Void, AuditError> logKeyRotation(KeyRotationEvent event) {
            return voidSuccess();
        }

        @Override
        public Result<Void, AuditError> logSecurityEvent(SecurityEvent event) {
            securityEvents.add(event);
            return voidSuccess();
        }

        @Override
        public Result<Void, AuditError> logKeyAccess(KeyAccessEvent event) {
            return voidSuccess();
        }

        @Override
        public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) {
            return voidSuccess();
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private static Result<Void, AuditError> voidSuccess() {
            return (Result<Void, AuditError>) (Result) Result.success(Unit.unit());
        }
    }
}
