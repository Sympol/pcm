package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.AlgorithmDeprecationPolicy;
import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AlgorithmDeprecationPolicy}.
 *
 * <p>Covers deprecation notice creation, isDeprecated checks, removal eligibility,
 * and notice retrieval.
 */
class AlgorithmDeprecationPolicyTest {

    private AlgorithmDeprecationPolicy policy;

    @BeforeEach
    void setUp() {
        policy = new AlgorithmDeprecationPolicy();
    }

    @Test
    @DisplayName("deprecate sets a notice with removal date ~365 days after deprecation")
    void deprecate_setsNoticeWithCorrectRemovalDate() {
        Instant before = Instant.now();
        policy.deprecate(EncryptionAlgorithm.AES_256_CBC_HMAC, "Upgrading to GCM");
        Instant after = Instant.now();

        Optional<AlgorithmDeprecationPolicy.DeprecationNotice> notice =
                policy.getNotice(EncryptionAlgorithm.AES_256_CBC_HMAC);

        assertTrue(notice.isPresent(), "Notice should be present after deprecation");

        Instant removalDate = notice.get().removalDate();
        Instant expectedMin = before.plus(365, ChronoUnit.DAYS);
        Instant expectedMax = after.plus(365, ChronoUnit.DAYS);

        assertFalse(removalDate.isBefore(expectedMin),
                "Removal date should be at least 365 days after deprecation");
        assertFalse(removalDate.isAfter(expectedMax),
                "Removal date should not be more than 365 days after deprecation");
    }

    @Test
    @DisplayName("isDeprecated returns true after deprecation")
    void isDeprecated_returnsTrueAfterDeprecation() {
        policy.deprecate(EncryptionAlgorithm.AES_256_CBC_HMAC, "Legacy algorithm");

        assertTrue(policy.isDeprecated(EncryptionAlgorithm.AES_256_CBC_HMAC));
    }

    @Test
    @DisplayName("isDeprecated returns false for non-deprecated algorithm")
    void isDeprecated_returnsFalseForNonDeprecatedAlgorithm() {
        assertFalse(policy.isDeprecated(EncryptionAlgorithm.AES_256_GCM));
    }

    @Test
    @DisplayName("isEligibleForRemoval returns false before removal date")
    void isEligibleForRemoval_returnsFalseBeforeRemovalDate() {
        policy.deprecate(EncryptionAlgorithm.AES_256_CBC_HMAC, "Legacy algorithm");

        // Removal date is 365 days away — should not be eligible yet
        assertFalse(policy.isEligibleForRemoval(EncryptionAlgorithm.AES_256_CBC_HMAC),
                "Algorithm should not be eligible for removal before the 365-day notice period");
    }

    @Test
    @DisplayName("getNotice returns empty for non-deprecated algorithm")
    void getNotice_returnsEmptyForNonDeprecatedAlgorithm() {
        Optional<AlgorithmDeprecationPolicy.DeprecationNotice> notice =
                policy.getNotice(EncryptionAlgorithm.AES_256_GCM);

        assertTrue(notice.isEmpty(), "Notice should be empty for non-deprecated algorithm");
    }
}
