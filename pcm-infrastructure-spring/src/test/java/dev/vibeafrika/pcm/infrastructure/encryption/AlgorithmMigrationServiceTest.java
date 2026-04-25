package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;
import dev.vibeafrika.pcm.domain.encryption.MigrationError;
import dev.vibeafrika.pcm.domain.encryption.MigrationId;
import dev.vibeafrika.pcm.domain.encryption.MigrationStatus;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.Unit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AlgorithmMigrationService}.
 *
 * <p>Covers:
 * <ul>
 *   <li>Parallel algorithm operation</li>
 *   <li>Gradual rollout</li>
 *   <li>Rollback procedures</li>
 * </ul>
 */
class AlgorithmMigrationServiceTest {

    private AlgorithmMigrationService service;

    private static final EncryptionAlgorithm OLD = EncryptionAlgorithm.AES_256_CBC_HMAC;
    private static final EncryptionAlgorithm NEW = EncryptionAlgorithm.AES_256_GCM;

    @BeforeEach
    void setUp() {
        service = new AlgorithmMigrationService();
    }

    // =========================================================================
    // Parallel algorithm operation 
    // =========================================================================

    @Test
    @DisplayName("startMigration with valid params returns a non-null MigrationId")
    void startMigration_withValidParams_returnsSuccessId() {
        Result<MigrationId, MigrationError> result = service.startMigration(OLD, NEW, 10);

        assertTrue(result.isSuccess(), "startMigration should succeed with valid params");
        assertNotNull(result.getValue().orElse(null), "MigrationId must not be null");
    }

    @Test
    @DisplayName("selectAlgorithm with no active migration returns the default algorithm")
    void selectAlgorithm_withNoActiveMigration_returnsDefault() {
        EncryptionAlgorithm selected = service.selectAlgorithm(OLD);

        assertEquals(OLD, selected, "Should return default algorithm when no migration is active");
    }

    @Test
    @DisplayName("selectAlgorithm at 0% rollout always returns old algorithm")
    void selectAlgorithm_withZeroPercentRollout_alwaysReturnsOldAlgorithm() {
        service.startMigration(OLD, NEW, 0);

        // Run many times to confirm it never routes to the new algorithm
        for (int i = 0; i < 200; i++) {
            assertEquals(OLD, service.selectAlgorithm(OLD),
                    "At 0% rollout, should always return old algorithm");
        }
    }

    @Test
    @DisplayName("selectAlgorithm at 100% rollout always returns new algorithm")
    void selectAlgorithm_withHundredPercentRollout_alwaysReturnsNewAlgorithm() {
        service.startMigration(OLD, NEW, 100);

        // Run many times to confirm it always routes to the new algorithm
        for (int i = 0; i < 200; i++) {
            assertEquals(NEW, service.selectAlgorithm(OLD),
                    "At 100% rollout, should always return new algorithm");
        }
    }

    // =========================================================================
    // Gradual rollout
    // =========================================================================

    @Test
    @DisplayName("startMigration at 1% rollout succeeds")
    void startMigration_withOnePercentRollout_succeeds() {
        Result<MigrationId, MigrationError> result = service.startMigration(OLD, NEW, 1);

        assertTrue(result.isSuccess(), "Starting migration at 1% rollout should succeed");
    }

    @Test
    @DisplayName("updateRolloutPercentage is reflected in getRolloutPercentage")
    void updateRolloutPercentage_increasesRollout() {
        MigrationId id = service.startMigration(OLD, NEW, 10).getValue().orElseThrow();

        Result<Unit, MigrationError> updateResult = service.updateRolloutPercentage(id, 50);
        assertTrue(updateResult.isSuccess(), "updateRolloutPercentage should succeed");

        Result<Integer, MigrationError> percentResult = service.getRolloutPercentage(id);
        assertTrue(percentResult.isSuccess());
        assertEquals(50, percentResult.getValue().orElseThrow(),
                "Rollout percentage should be updated to 50");
    }

    @Test
    @DisplayName("startMigration with percentage > 100 returns INVALID_ROLLOUT_PERCENTAGE")
    void startMigration_withInvalidPercentage_returnsError() {
        Result<MigrationId, MigrationError> tooHigh = service.startMigration(OLD, NEW, 101);
        assertTrue(tooHigh.isFailure());
        assertEquals(MigrationError.INVALID_ROLLOUT_PERCENTAGE, tooHigh.getError().orElseThrow());

        Result<MigrationId, MigrationError> negative = service.startMigration(OLD, NEW, -1);
        assertTrue(negative.isFailure());
        assertEquals(MigrationError.INVALID_ROLLOUT_PERCENTAGE, negative.getError().orElseThrow());
    }

    @Test
    @DisplayName("startMigration with duplicate active migration returns MIGRATION_ALREADY_ACTIVE")
    void startMigration_withDuplicateActiveMigration_returnsError() {
        service.startMigration(OLD, NEW, 10);

        Result<MigrationId, MigrationError> duplicate = service.startMigration(OLD, NEW, 20);

        assertTrue(duplicate.isFailure());
        assertEquals(MigrationError.MIGRATION_ALREADY_ACTIVE, duplicate.getError().orElseThrow());
    }

    // =========================================================================
    // Rollback procedures 
    // =========================================================================

    @Test
    @DisplayName("rollback immediately after start succeeds and sets status to ROLLED_BACK")
    void rollback_withinWindow_succeeds() {
        MigrationId id = service.startMigration(OLD, NEW, 10).getValue().orElseThrow();

        Result<Unit, MigrationError> rollbackResult = service.rollback(id);

        assertTrue(rollbackResult.isSuccess(), "Rollback within window should succeed");
    }

    @Test
    @DisplayName("rollback after 24h window expired returns ROLLBACK_WINDOW_EXPIRED")
    void rollback_afterWindowExpired_returnsError() throws Exception {
        MigrationId id = service.startMigration(OLD, NEW, 10).getValue().orElseThrow();

        // Use reflection to backdate the startedAt field on the stored record
        Field migrationsField = AlgorithmMigrationService.class.getDeclaredField("migrations");
        migrationsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        ConcurrentHashMap<MigrationId, dev.vibeafrika.pcm.domain.encryption.AlgorithmMigrationRecord> migrations =
                (ConcurrentHashMap<MigrationId, dev.vibeafrika.pcm.domain.encryption.AlgorithmMigrationRecord>) migrationsField.get(service);

        dev.vibeafrika.pcm.domain.encryption.AlgorithmMigrationRecord original = migrations.get(id);

        // Create a backdated record by reconstructing via withRolloutPercentage (preserves startedAt)
        // We need to replace the record with one that has a startedAt > 24h ago.
        // AlgorithmMigrationRecord.create is the only factory — use it directly.
        Instant backdated = Instant.now().minus(25, ChronoUnit.HOURS);
        dev.vibeafrika.pcm.domain.encryption.AlgorithmMigrationRecord expired =
                dev.vibeafrika.pcm.domain.encryption.AlgorithmMigrationRecord.create(
                        id,
                        original.getFromAlgorithm(),
                        original.getToAlgorithm(),
                        original.getRolloutPercentage(),
                        backdated);
        migrations.put(id, expired);

        Result<Unit, MigrationError> result = service.rollback(id);

        assertTrue(result.isFailure());
        assertEquals(MigrationError.ROLLBACK_WINDOW_EXPIRED, result.getError().orElseThrow());
    }

    @Test
    @DisplayName("rollback of unknown migration returns MIGRATION_NOT_FOUND")
    void rollback_unknownMigration_returnsError() {
        MigrationId unknown = MigrationId.generate();

        Result<Unit, MigrationError> result = service.rollback(unknown);

        assertTrue(result.isFailure());
        assertEquals(MigrationError.MIGRATION_NOT_FOUND, result.getError().orElseThrow());
    }

    @Test
    @DisplayName("getMigrationStatus after rollback returns ROLLED_BACK")
    void getMigrationStatus_afterRollback_isRolledBack() {
        MigrationId id = service.startMigration(OLD, NEW, 10).getValue().orElseThrow();
        service.rollback(id);

        Result<MigrationStatus, MigrationError> statusResult = service.getMigrationStatus(id);

        assertTrue(statusResult.isSuccess());
        assertEquals(MigrationStatus.ROLLED_BACK, statusResult.getValue().orElseThrow());
    }
}
