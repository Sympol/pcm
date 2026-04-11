package dev.vibeafrika.pcm.infrastructure.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Side-channel protection configuration and documentation.
 *
 * <h2>BouncyCastle Provider</h2>
 * <p>BouncyCastle is registered as a JCE security provider. Its AES-GCM and
 * HMAC-SHA256 implementations are designed with side-channel resistance in mind,
 * including protection against simple power analysis (SPA) and differential power
 * analysis (DPA) in hardware-constrained environments.
 *
 * <p>The JDK's built-in {@code AES/GCM/NoPadding} cipher is used for encryption
 * (backed by AES-NI hardware acceleration where available). BouncyCastle is
 * available as a fallback and for additional algorithm support.
 *
 * <h2>Cache-Timing Attack Awareness </h2>
 * <p>Cache-timing attacks exploit CPU cache behaviour to infer secret values.
 * The following mitigations are applied in this codebase:
 *
 * <ul>
 *   <li><b>Authentication tag comparison</b>: uses {@link dev.vibeafrika.pcm.domain.encryption.ConstantTime#verifyAuthTag}
 *       which delegates to {@link java.security.MessageDigest#isEqual} — a JDK method
 *       documented to run in constant time.</li>
 *   <li><b>HMAC verification</b>: uses {@link dev.vibeafrika.pcm.domain.encryption.ConstantTime#verifyHmac}
 *       for the same reason.</li>
 *   <li><b>Key equality</b>: {@link dev.vibeafrika.pcm.domain.encryption.DEK#equals} uses
 *       {@link dev.vibeafrika.pcm.domain.encryption.ConstantTime#equals} to avoid
 *       short-circuit byte comparison.</li>
 *   <li><b>No secret-dependent branching</b>: encryption and decryption paths do not
 *       branch on plaintext or key material values.</li>
 *   <li><b>AES-NI</b>: hardware AES instructions execute in constant time on supported
 *       CPUs, eliminating table-lookup cache timing leakage present in software AES.</li>
 * </ul>
 *
 * <h2>Remaining Risks</h2>
 * <p>Full elimination of cache-timing attacks requires hardware-level isolation
 * (e.g., HSM). The mitigations above reduce risk significantly for software
 * implementations but do not provide absolute guarantees against a co-located
 * attacker with fine-grained cache access. Annual penetration testing
 * should include side-channel analysis.
 */
public final class SideChannelProtection {

    private SideChannelProtection() {
        // utility class
    }

    /**
     * Registers BouncyCastle as a JCE security provider if not already registered.
     *
     * <p>Call this once during application startup (e.g., from a Spring
     * {@code @Configuration} class or {@code @PostConstruct} method).
     */
    public static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
