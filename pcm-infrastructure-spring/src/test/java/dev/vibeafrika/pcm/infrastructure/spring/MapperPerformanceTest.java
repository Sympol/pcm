package dev.vibeafrika.pcm.infrastructure.spring;

import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.mapper.ConsentMapper;
import dev.vibeafrika.pcm.preference.domain.model.*;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.mapper.PreferenceMapper;
import dev.vibeafrika.pcm.profile.domain.model.*;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.mapper.ProfileMapper;
import dev.vibeafrika.pcm.segment.domain.model.*;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.mapper.SegmentMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Task 33.2: Mapper performance validation across all four bounded contexts.
 *
 * Verifies that entity mapping (domain ↔ JPA) completes in under 1ms per entity
 * for all four services: Preference, Segment, Profile, Consent.
 */
@DisplayName("Mapper Performance Validation — All Services")
class MapperPerformanceTest {

    private static final Logger log = LoggerFactory.getLogger(MapperPerformanceTest.class);

    /** Maximum allowed average conversion time per entity in nanoseconds (1ms). */
    private static final long MAX_AVG_NS = 1_000_000L;

    private static final int WARMUP_ITERATIONS  = 1_000;
    private static final int MEASURE_ITERATIONS = 10_000;

    // =========================================================================
    // Preference Mapper
    // =========================================================================

    @Test
    @DisplayName("PreferenceMapper.toJpaEntity average time < 1ms")
    void preferenceMapper_toJpaEntity_averageUnder1ms() {
        Preference preference = buildPreference();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            PreferenceMapper.toJpaEntity(preference);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            PreferenceMapper.toJpaEntity(preference);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] PreferenceMapper.toJpaEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("PreferenceMapper.toJpaEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    @Test
    @DisplayName("PreferenceMapper.toDomainEntity average time < 1ms")
    void preferenceMapper_toDomainEntity_averageUnder1ms() {
        PreferenceJpaEntity entity = buildPreferenceJpaEntity();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            PreferenceMapper.toDomainEntity(entity);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            PreferenceMapper.toDomainEntity(entity);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] PreferenceMapper.toDomainEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("PreferenceMapper.toDomainEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    // =========================================================================
    // Segment Mapper
    // =========================================================================

    @Test
    @DisplayName("SegmentMapper.toJpaEntity average time < 1ms")
    void segmentMapper_toJpaEntity_averageUnder1ms() {
        Segment segment = buildSegment();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            SegmentMapper.toJpaEntity(segment);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            SegmentMapper.toJpaEntity(segment);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] SegmentMapper.toJpaEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("SegmentMapper.toJpaEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    @Test
    @DisplayName("SegmentMapper.toDomainEntity average time < 1ms")
    void segmentMapper_toDomainEntity_averageUnder1ms() {
        SegmentJpaEntity entity = buildSegmentJpaEntity();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            SegmentMapper.toDomainEntity(entity);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            SegmentMapper.toDomainEntity(entity);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] SegmentMapper.toDomainEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("SegmentMapper.toDomainEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    // =========================================================================
    // Profile Mapper
    // =========================================================================

    @Test
    @DisplayName("ProfileMapper.toJpaEntity average time < 1ms")
    void profileMapper_toJpaEntity_averageUnder1ms() {
        Profile profile = buildProfile();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            ProfileMapper.toJpaEntity(profile);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            ProfileMapper.toJpaEntity(profile);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] ProfileMapper.toJpaEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("ProfileMapper.toJpaEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    @Test
    @DisplayName("ProfileMapper.toDomainEntity average time < 1ms ")
    void profileMapper_toDomainEntity_averageUnder1ms() {
        ProfileJpaEntity entity = buildProfileJpaEntity();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            ProfileMapper.toDomainEntity(entity);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            ProfileMapper.toDomainEntity(entity);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] ProfileMapper.toDomainEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("ProfileMapper.toDomainEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    // =========================================================================
    // Consent Mapper
    // =========================================================================

    @Test
    @DisplayName("ConsentMapper.toJpaEntity average time < 1ms")
    void consentMapper_toJpaEntity_averageUnder1ms() {
        Consent consent = buildConsent();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            ConsentMapper.toJpaEntity(consent);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            ConsentMapper.toJpaEntity(consent);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] ConsentMapper.toJpaEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("ConsentMapper.toJpaEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    @Test
    @DisplayName("ConsentMapper.toDomainEntity average time < 1ms")
    void consentMapper_toDomainEntity_averageUnder1ms() {
        ConsentJpaEntity entity = buildConsentJpaEntity();

        // Warm up
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            ConsentMapper.toDomainEntity(entity);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_ITERATIONS; i++) {
            ConsentMapper.toDomainEntity(entity);
        }
        long totalNs = System.nanoTime() - start;
        long avgNs = totalNs / MEASURE_ITERATIONS;

        log.info("[MapperPerf] ConsentMapper.toDomainEntity — avg={}ns  total={}ms  (n={})",
                avgNs, totalNs / 1_000_000, MEASURE_ITERATIONS);

        assertTrue(avgNs < MAX_AVG_NS,
                String.format("ConsentMapper.toDomainEntity avg %dns exceeds 1ms threshold", avgNs));
    }

    // =========================================================================
    // Domain entity builders
    // =========================================================================

    private Preference buildPreference() {
        return Preference.reconstitute(
            PreferenceId.generate(),
            dev.vibeafrika.pcm.preference.domain.model.TenantId.of("tenant-perf"),
            dev.vibeafrika.pcm.preference.domain.model.ProfileId.generate(),
            Map.of("theme", "dark", "language", "en", "timezone", "UTC"),
            Instant.now(),
            false
        );
    }

    private PreferenceJpaEntity buildPreferenceJpaEntity() {
        PreferenceJpaEntity entity = new PreferenceJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setTenantId("tenant-perf");
        entity.setProfileId(UUID.randomUUID());
        entity.setSettings(new HashMap<>(Map.of("theme", "dark", "language", "en")));
        entity.setLastUpdated(Instant.now());
        entity.setDeleted(false);
        return entity;
    }

    private Segment buildSegment() {
        return Segment.reconstitute(
            SegmentId.generate(),
            dev.vibeafrika.pcm.segment.domain.model.TenantId.of("tenant-perf"),
            dev.vibeafrika.pcm.segment.domain.model.ProfileId.generate(),
            Set.of("sports", "tech", "music"),
            Map.of("relevance", 0.85, "engagement", 0.72, "recency", 0.91),
            Instant.now()
        );
    }

    private SegmentJpaEntity buildSegmentJpaEntity() {
        SegmentJpaEntity entity = new SegmentJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setTenantId("tenant-perf");
        entity.setProfileId(UUID.randomUUID());
        entity.setTags(new HashSet<>(Set.of("sports", "tech", "music")));
        entity.setScores(new HashMap<>(Map.of("relevance", 0.85, "engagement", 0.72)));
        entity.setLastUpdated(Instant.now());
        return entity;
    }

    private Profile buildProfile() {
        return Profile.reconstitute(
            dev.vibeafrika.pcm.profile.domain.model.ProfileId.generate(),
            dev.vibeafrika.pcm.profile.domain.model.TenantId.of("tenant-perf"),
            Handle.of("perfuser"),
            Map.of("age", "30", "country", "US"),
            Instant.now(),
            Instant.now(),
            1L,
            false
        );
    }

    private ProfileJpaEntity buildProfileJpaEntity() {
        ProfileJpaEntity entity = new ProfileJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setTenantId("tenant-perf");
        entity.setHandle("perfuser");
        entity.setAttributes(new HashMap<>(Map.of("age", "30", "country", "US")));
        entity.setCreatedAt(Instant.now());
        entity.setUpdatedAt(Instant.now());
        entity.setVersion(1L);
        entity.setDeleted(false);
        return entity;
    }

    private Consent buildConsent() {
        return Consent.reconstitute(
            ConsentId.generate(),
            dev.vibeafrika.pcm.consent.domain.model.ProfileId.of(UUID.randomUUID()),
            dev.vibeafrika.pcm.consent.domain.model.TenantId.of("tenant-perf"),
            ConsentPurpose.of("analytics"),
            ConsentScope.of("page-views"),
            ConsentStatus.GRANTED,
            List.of(new Consent.ConsentEvent(ConsentStatus.GRANTED, Instant.now())),
            Instant.now(),
            Instant.now(),
            1L
        );
    }

    private ConsentJpaEntity buildConsentJpaEntity() {
        ConsentJpaEntity entity = new ConsentJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("tenant-perf");
        entity.setPurpose("analytics");
        entity.setScope("page-views");
        entity.setStatus(ConsentStatus.GRANTED);
        entity.setCreatedAt(Instant.now());
        entity.setUpdatedAt(Instant.now());
        entity.setVersion(1L);
        // No events needed for toDomainEntity — empty list is valid
        return entity;
    }
}
