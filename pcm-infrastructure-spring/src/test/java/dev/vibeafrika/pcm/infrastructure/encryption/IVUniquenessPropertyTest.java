package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.IV;
import dev.vibeafrika.pcm.domain.encryption.IVCounterError;
import dev.vibeafrika.pcm.domain.encryption.Result;
import net.jqwik.api.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for IV uniqueness.
 *
 * <p>These tests verify Property 5: IV Uniqueness — for any sequence of encryption
 * operations with the same DEK, all generated IVs shall be unique.
 */
class IVUniquenessPropertyTest {

    /**
     *
     * Property 5: IV Uniqueness
     *
     * For any DEK ID and any number of IV generation calls (1–500), all generated IVs
     * must be distinct. The counter-based approach (randomBase || counter) guarantees
     * uniqueness because the counter is monotonically increasing within a single DEK.
     */
    @Property(tries = 200)
    @Label("All IVs generated for the same DEK are unique")
    void allIVsGeneratedForSameDEKAreUnique(
            @ForAll("validDekId") UUID dekId,
            @ForAll("ivCount") int count) {

        IVCounterImpl ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());

        List<IV> generatedIVs = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertThat(result.isSuccess())
                    .as("IV generation %d should succeed for DEK %s", i, dekId)
                    .isTrue();
            generatedIVs.add(result.getValue().orElseThrow());
        }

        // All IVs must be unique — a Set will deduplicate equal elements
        Set<IV> uniqueIVs = new HashSet<>(generatedIVs);
        assertThat(uniqueIVs)
                .as("Expected %d unique IVs but found %d duplicates", count, count - uniqueIVs.size())
                .hasSize(count);
    }

    /**
     *
     * Property 5 (cross-DEK variant): IVs generated for different DEKs are also unique
     * because each DEK gets its own independent random base.
     */
    @Property(tries = 100)
    @Label("IVs generated for different DEKs are unique across DEKs")
    void ivsGeneratedForDifferentDEKsAreUnique(
            @ForAll("twoDifferentDekIds") List<UUID> dekIds) {

        IVCounterImpl ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());

        List<IV> allIVs = new ArrayList<>();
        for (UUID dekId : dekIds) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertThat(result.isSuccess())
                    .as("IV generation should succeed for DEK %s", dekId)
                    .isTrue();
            allIVs.add(result.getValue().orElseThrow());
        }

        Set<IV> uniqueIVs = new HashSet<>(allIVs);
        assertThat(uniqueIVs)
                .as("IVs across different DEKs should all be unique")
                .hasSize(allIVs.size());
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    @Provide
    Arbitrary<UUID> validDekId() {
        return Arbitraries.randomValue(random -> UUID.randomUUID());
    }

    /**
     * Generates counts between 1 and 500 — large enough to catch counter bugs
     * while staying well below the overflow threshold (2^31).
     */
    @Provide
    Arbitrary<Integer> ivCount() {
        return Arbitraries.integers().between(1, 500);
    }

    /**
     * Generates a list of exactly 2 distinct DEK IDs.
     */
    @Provide
    Arbitrary<List<UUID>> twoDifferentDekIds() {
        return Arbitraries.randomValue(random -> {
            UUID first = UUID.randomUUID();
            UUID second = UUID.randomUUID();
            // Ensure they are actually different (astronomically unlikely to collide, but be safe)
            while (second.equals(first)) {
                second = UUID.randomUUID();
            }
            List<UUID> ids = new ArrayList<>();
            ids.add(first);
            ids.add(second);
            return ids;
        });
    }
}
