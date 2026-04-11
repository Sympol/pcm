package dev.vibeafrika.pcm.infrastructure.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

/**
 * Detects and reports AES-NI hardware acceleration availability.
 *
 * <p>AES-NI is used automatically by the JVM's SunJCE provider on x86/x64 hardware
 * that supports it. This class makes that detection explicit and verifiable at startup
 * (Requirement 10.9).
 *
 * <p>This is a plain utility class with no Spring dependencies.
 */
public final class HardwareAccelerationConfig {

    private static final Logger logger = LoggerFactory.getLogger(HardwareAccelerationConfig.class);
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String SUN_JCE_PROVIDER = "SunJCE";

    private final boolean aesNiAvailable;
    private final String preferredProvider;

    private HardwareAccelerationConfig(boolean aesNiAvailable, String preferredProvider) {
        this.aesNiAvailable = aesNiAvailable;
        this.preferredProvider = preferredProvider;
    }

    /**
     * Detects hardware acceleration availability and returns a configured instance.
     *
     * @return a new {@code HardwareAccelerationConfig} reflecting the current JVM capabilities
     */
    public static HardwareAccelerationConfig detect() {
        boolean available = isAesNiAvailable();
        String provider = getPreferredProvider();
        logger.info("AES-NI hardware acceleration: {}", available ? "available" : "not detected");
        logger.info("AES/GCM cipher provider: {}", provider);
        return new HardwareAccelerationConfig(available, provider);
    }

    /**
     * Returns {@code true} if AES-NI hardware acceleration is likely available.
     *
     * <p>Detection works by checking whether the default JVM provider for AES/GCM/NoPadding
     * is SunJCE, which uses AES-NI intrinsics on supported x86/x64 hardware.
     *
     * @return {@code true} if SunJCE is the active provider (AES-NI likely in use)
     */
    public static boolean isAesNiAvailable() {
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            String providerName = cipher.getProvider().getName();
            // SunJCE uses AES-NI intrinsics on supported hardware
            return SUN_JCE_PROVIDER.equals(providerName);
        } catch (Exception e) {
            logger.warn("Could not probe AES/GCM cipher provider for AES-NI detection", e);
            return false;
        }
    }

    /**
     * Returns the name of the preferred JCE provider for AES/GCM operations.
     *
     * @return the provider name (e.g. {@code "SunJCE"}), never {@code null}
     */
    public static String getPreferredProvider() {
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            return cipher.getProvider().getName();
        } catch (Exception e) {
            logger.warn("Could not determine preferred AES/GCM provider, falling back to default", e);
            return "default";
        }
    }

    /** @return whether AES-NI acceleration was detected on this instance */
    public boolean isAesNiDetected() {
        return aesNiAvailable;
    }

    /** @return the provider name resolved at detection time */
    public String getProvider() {
        return preferredProvider;
    }
}
