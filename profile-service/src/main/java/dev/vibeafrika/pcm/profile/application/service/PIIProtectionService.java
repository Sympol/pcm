package dev.vibeafrika.pcm.profile.application.service;

import dev.vibeafrika.pcm.common.security.PiiProtectionProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Application service to coordinate PII protection (encryption/decryption).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PIIProtectionService {

    private final PiiProtectionProvider piiProtectionProvider;

    private static final Set<String> PII_KEYS = Set.of("email", "fullName", "phoneNumber");

    /**
     * Encrypts PII fields in the attributes map.
     */
    public Map<String, Object> protect(Map<String, Object> attributes) {
        if (attributes == null)
            return null;
        log.info("Protecting PII fields: {}", attributes.keySet());
        Map<String, Object> protectedAttributes = new HashMap<>(attributes);
        for (String key : PII_KEYS) {
            if (protectedAttributes.containsKey(key)) {
                Object value = protectedAttributes.get(key);
                if (value instanceof String plaintext) {
                    String encrypted = piiProtectionProvider.encrypt(plaintext);
                    log.info("Key {}: plaintext encrypted successfully", key);
                    protectedAttributes.put(key, encrypted);
                }
            }
        }
        return protectedAttributes;
    }

    /**
     * Decrypts PII fields in the attributes map.
     */
    public Map<String, Object> unprotect(Map<String, Object> attributes) {
        if (attributes == null)
            return null;
        log.info("Unprotecting PII fields: {}", attributes.keySet());
        Map<String, Object> unprotectedAttributes = new HashMap<>(attributes);
        for (String key : PII_KEYS) {
            if (unprotectedAttributes.containsKey(key)) {
                Object value = unprotectedAttributes.get(key);
                if (value instanceof String ciphertext) {
                    String decrypted = piiProtectionProvider.decrypt(ciphertext);
                    log.info("Key {}: ciphertext decrypted successfully", key);
                    unprotectedAttributes.put(key, decrypted);
                }
            }
        }
        return unprotectedAttributes;
    }
}
