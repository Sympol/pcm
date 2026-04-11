package dev.vibeafrika.pcm.infrastructure.spring.encryption.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * Spring Boot configuration for mutual TLS (mTLS) used in KMS communication.
 *
 * <p>Configures an {@link SSLContext} bean that enforces bidirectional certificate
 * verification — both the client (this service) and the KMS server must present
 * valid certificates. 
 *
 * <p>Configuration properties are bound from {@code pcm.encryption.network.mtls.*}:
 * <pre>
 * pcm:
 *   encryption:
 *     network:
 *       mtls:
 *         enabled: true
 *         keystore-path: /etc/pcm/certs/client.p12
 *         keystore-password: changeit
 *         keystore-type: PKCS12
 *         truststore-path: /etc/pcm/certs/truststore.jks
 *         truststore-password: changeit
 *         truststore-type: JKS
 *         tls-protocol: TLSv1.3
 * </pre>
 */
@Configuration
@EnableConfigurationProperties(MtlsConfiguration.MtlsProperties.class)
public class MtlsConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(MtlsConfiguration.class);

    private final MtlsProperties properties;

    public MtlsConfiguration(MtlsProperties properties) {
        this.properties = properties;
    }

    /**
     * Provides a configured {@link SSLContext} for KMS HTTP clients.
     *
     * <p>When mTLS is disabled (e.g. in local development), returns the JVM default
     * SSL context so that callers can always inject this bean without null checks.
     *
     * @return an {@link SSLContext} configured for mutual TLS
     * @throws IllegalStateException if mTLS is enabled but the keystore/truststore
     *                               cannot be loaded
     */
    @Bean(name = "kmsSslContext")
    public SSLContext kmsSslContext() {
        if (!properties.isEnabled()) {
            logger.warn("mTLS is DISABLED for KMS communication. " +
                        "This is only acceptable in non-production environments.");
            try {
                return SSLContext.getDefault();
            } catch (Exception e) {
                throw new IllegalStateException("Failed to obtain default SSLContext", e);
            }
        }

        logger.info("Configuring mTLS SSLContext for KMS communication " +
                    "(protocol={}, keystore={}, truststore={})",
                    properties.getTlsProtocol(),
                    properties.getKeystorePath(),
                    properties.getTruststorePath());

        try {
            KeyStore keyStore = loadKeyStore(
                    properties.getKeystorePath(),
                    properties.getKeystorePassword(),
                    properties.getKeystoreType());

            KeyStore trustStore = loadKeyStore(
                    properties.getTruststorePath(),
                    properties.getTruststorePassword(),
                    properties.getTruststoreType());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, properties.getKeystorePassword());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance(properties.getTlsProtocol());
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            logger.info("mTLS SSLContext configured successfully");
            return sslContext;

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to configure mTLS SSLContext for KMS communication", e);
        }
    }

    /**
     * Loads a {@link KeyStore} from the given file path.
     *
     * @param path     filesystem path to the keystore file
     * @param password keystore password
     * @param type     keystore type (PKCS12 or JKS)
     * @return the loaded {@link KeyStore}
     */
    private KeyStore loadKeyStore(String path, char[] password, String type) throws Exception {
        KeyStore ks = KeyStore.getInstance(type);
        try (InputStream is = Files.newInputStream(Paths.get(path))) {
            ks.load(is, password);
        }
        return ks;
    }

    // -------------------------------------------------------------------------
    // Configuration properties
    // -------------------------------------------------------------------------

    /**
     * Strongly-typed configuration properties for mTLS, bound from
     * {@code pcm.encryption.network.mtls.*}.
     */
    @ConfigurationProperties(prefix = "pcm.encryption.network.mtls")
    public static class MtlsProperties {

        /** Whether mTLS is enabled. Defaults to {@code false} for safety in tests. */
        private boolean enabled = false;

        /** Filesystem path to the client keystore (PKCS12 or JKS). */
        private String keystorePath = "";

        /** Password for the client keystore. */
        private char[] keystorePassword = new char[0];

        /** Keystore type. Defaults to PKCS12. */
        private String keystoreType = "PKCS12";

        /** Filesystem path to the truststore containing KMS CA certificates. */
        private String truststorePath = "";

        /** Password for the truststore. */
        private char[] truststorePassword = new char[0];

        /** Truststore type. Defaults to JKS. */
        private String truststoreType = "JKS";

        /** TLS protocol version. Defaults to TLSv1.3. */
        private String tlsProtocol = "TLSv1.3";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getKeystorePath() { return keystorePath; }
        public void setKeystorePath(String keystorePath) { this.keystorePath = keystorePath; }

        public char[] getKeystorePassword() { return keystorePassword; }
        public void setKeystorePassword(char[] keystorePassword) { this.keystorePassword = keystorePassword; }

        public String getKeystoreType() { return keystoreType; }
        public void setKeystoreType(String keystoreType) { this.keystoreType = keystoreType; }

        public String getTruststorePath() { return truststorePath; }
        public void setTruststorePath(String truststorePath) { this.truststorePath = truststorePath; }

        public char[] getTruststorePassword() { return truststorePassword; }
        public void setTruststorePassword(char[] truststorePassword) { this.truststorePassword = truststorePassword; }

        public String getTruststoreType() { return truststoreType; }
        public void setTruststoreType(String truststoreType) { this.truststoreType = truststoreType; }

        public String getTlsProtocol() { return tlsProtocol; }
        public void setTlsProtocol(String tlsProtocol) { this.tlsProtocol = tlsProtocol; }
    }
}
