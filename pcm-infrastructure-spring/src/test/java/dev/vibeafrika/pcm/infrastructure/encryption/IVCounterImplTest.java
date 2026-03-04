package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.IV;
import dev.vibeafrika.pcm.domain.encryption.IVCounter;
import dev.vibeafrika.pcm.domain.encryption.IVCounterError;
import dev.vibeafrika.pcm.domain.encryption.IVCounterState;
import dev.vibeafrika.pcm.domain.encryption.IVCounterStorage;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.Unit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for IVCounterImpl.
 * 
 * Tests IV generation, counter persistence, overflow detection, and state management.
 */
class IVCounterImplTest {

    private IVCounterStorage storage;
    private IVCounterImpl ivCounter;

    @BeforeEach
    void setUp() {
        storage = new InMemoryIVCounterStorage();
        ivCounter = new IVCounterImpl(storage);
    }

    @Test
    void testGenerateIV_FirstTime_Success() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act
        Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);

        // Assert
        assertTrue(result.isSuccess());
        IV iv = result.getValue().get();
        assertNotNull(iv);
        assertEquals(12, iv.getLength()); // 96 bits = 12 bytes
    }

    @Test
    void testGenerateIV_Multiple_UniqueIVs() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act - Generate 10 IVs
        IV[] ivs = new IV[10];
        for (int i = 0; i < 10; i++) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertTrue(result.isSuccess());
            ivs[i] = result.getValue().get();
        }

        // Assert - All IVs should be unique
        for (int i = 0; i < ivs.length; i++) {
            for (int j = i + 1; j < ivs.length; j++) {
                assertNotEquals(ivs[i], ivs[j], 
                    "IVs at positions " + i + " and " + j + " should be different");
            }
        }
    }

    @Test
    void testGenerateIV_NullDekId_Failure() {
        // Act
        Result<IV, IVCounterError> result = ivCounter.generateIV(null);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("cannot be null"));
    }

    @Test
    void testGenerateIV_DifferentDEKs_IndependentCounters() {
        // Arrange
        UUID dekId1 = UUID.randomUUID();
        UUID dekId2 = UUID.randomUUID();

        // Act - Generate IVs for both DEKs
        Result<IV, IVCounterError> result1a = ivCounter.generateIV(dekId1);
        Result<IV, IVCounterError> result2a = ivCounter.generateIV(dekId2);
        Result<IV, IVCounterError> result1b = ivCounter.generateIV(dekId1);
        Result<IV, IVCounterError> result2b = ivCounter.generateIV(dekId2);

        // Assert - All should succeed
        assertTrue(result1a.isSuccess());
        assertTrue(result2a.isSuccess());
        assertTrue(result1b.isSuccess());
        assertTrue(result2b.isSuccess());

        // Assert - IVs for same DEK should be different
        assertNotEquals(result1a.getValue().get(), result1b.getValue().get());
        assertNotEquals(result2a.getValue().get(), result2b.getValue().get());
    }

    @Test
    void testPersistState_Every1000Increments() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act - Generate 1001 IVs
        for (int i = 0; i < 1001; i++) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertTrue(result.isSuccess(), "Failed at iteration " + i);
        }

        // Assert - State should be persisted at 1000
        Result<IVCounterState, IVCounterError> loadResult = storage.loadState(dekId);
        assertTrue(loadResult.isSuccess());
        IVCounterState state = loadResult.getValue().get();
        
        // Counter in storage should be at 1000 (last persisted), not 1001
        assertEquals(1000, state.getCounter());
        assertEquals(1000, state.getLastPersisted());
        
        // But the in-memory state should be at 1001
        Result<IVCounterState, IVCounterError> cacheState = ivCounter.loadState(dekId);
        assertTrue(cacheState.isSuccess());
        assertEquals(1001, cacheState.getValue().get().getCounter());
    }

    @Test
    void testPersistState_Manual_Success() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Generate a few IVs
        for (int i = 0; i < 5; i++) {
            ivCounter.generateIV(dekId);
        }

        // Act - Manually persist
        Result<Unit, IVCounterError> persistResult = ivCounter.persistState(dekId);

        // Assert
        assertTrue(persistResult.isSuccess());
        
        // Verify state was persisted
        Result<IVCounterState, IVCounterError> loadResult = storage.loadState(dekId);
        assertTrue(loadResult.isSuccess());
        IVCounterState state = loadResult.getValue().get();
        assertEquals(5, state.getCounter());
        assertEquals(5, state.getLastPersisted());
    }

    @Test
    void testPersistState_NullDekId_Failure() {
        // Act
        Result<Unit, IVCounterError> result = ivCounter.persistState(null);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
    }

    @Test
    void testPersistState_NoStateInCache_Failure() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act - Try to persist without generating any IVs
        Result<Unit, IVCounterError> result = ivCounter.persistState(dekId);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("No state found in cache"));
    }

    @Test
    void testLoadState_NewDEK_InitializesState() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act
        Result<IVCounterState, IVCounterError> result = ivCounter.loadState(dekId);

        // Assert
        assertTrue(result.isSuccess());
        IVCounterState state = result.getValue().get();
        assertEquals(dekId, state.getDekId());
        assertEquals(0, state.getCounter());
        assertEquals(0, state.getLastPersisted());
        assertNotEquals(0, state.getRandomBase()); // Should have random base
    }

    @Test
    void testLoadState_ExistingDEK_LoadsFromStorage() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Generate some IVs and persist
        for (int i = 0; i < 1000; i++) {
            ivCounter.generateIV(dekId);
        }
        ivCounter.persistState(dekId);

        // Create new counter instance (simulating restart)
        IVCounterImpl newCounter = new IVCounterImpl(storage);

        // Act
        Result<IVCounterState, IVCounterError> result = newCounter.loadState(dekId);

        // Assert
        assertTrue(result.isSuccess());
        IVCounterState state = result.getValue().get();
        assertEquals(1000, state.getCounter());
        assertEquals(1000, state.getLastPersisted());
    }

    @Test
    void testLoadState_NullDekId_Failure() {
        // Act
        Result<IVCounterState, IVCounterError> result = ivCounter.loadState(null);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
    }

    @Test
    void testResetState_Success() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Generate some IVs
        for (int i = 0; i < 10; i++) {
            ivCounter.generateIV(dekId);
        }

        // Act
        Result<Unit, IVCounterError> resetResult = ivCounter.resetState(dekId);

        // Assert
        assertTrue(resetResult.isSuccess());
        
        // Verify state was deleted from storage
        Result<IVCounterState, IVCounterError> loadResult = storage.loadState(dekId);
        assertTrue(loadResult.isFailure());
        assertEquals("IV_COUNTER_LOAD_FAILED", loadResult.getError().get().getCode());
    }

    @Test
    void testResetState_NullDekId_Failure() {
        // Act
        Result<Unit, IVCounterError> result = ivCounter.resetState(null);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
    }

    @Test
    void testCounterRecoveryAfterRestart() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Generate 1500 IVs (will persist at 1000)
        for (int i = 0; i < 1500; i++) {
            ivCounter.generateIV(dekId);
        }

        // Simulate restart by creating new counter instance
        IVCounterImpl newCounter = new IVCounterImpl(storage);

        // Act - Generate more IVs with new instance
        Result<IV, IVCounterError> result = newCounter.generateIV(dekId);

        // Assert
        assertTrue(result.isSuccess());
        
        // Verify counter continued from persisted value (1000)
        // Note: The counter in cache was at 1500, but only 1000 was persisted
        // After restart, it should load 1000 and increment to 1001
        Result<IVCounterState, IVCounterError> stateResult = newCounter.loadState(dekId);
        assertTrue(stateResult.isSuccess());
        // Counter should be at least 1001 (loaded 1000 + 1 from generateIV above)
        assertTrue(stateResult.getValue().get().getCounter() >= 1001);
    }

    @Test
    void testIVStructure_96Bits() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act
        Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);

        // Assert
        assertTrue(result.isSuccess());
        IV iv = result.getValue().get();
        
        // IV should be exactly 96 bits (12 bytes)
        assertEquals(12, iv.getLength());
        assertEquals(12, iv.getValue().length);
    }

    @Test
    void testRandomBaseUniqueness() {
        // Arrange - Create multiple DEKs
        UUID dekId1 = UUID.randomUUID();
        UUID dekId2 = UUID.randomUUID();
        UUID dekId3 = UUID.randomUUID();

        // Act - Load states to initialize random bases
        Result<IVCounterState, IVCounterError> state1 = ivCounter.loadState(dekId1);
        Result<IVCounterState, IVCounterError> state2 = ivCounter.loadState(dekId2);
        Result<IVCounterState, IVCounterError> state3 = ivCounter.loadState(dekId3);

        // Assert - All should succeed
        assertTrue(state1.isSuccess());
        assertTrue(state2.isSuccess());
        assertTrue(state3.isSuccess());

        // Assert - Random bases should be different (with very high probability)
        long base1 = state1.getValue().get().getRandomBase();
        long base2 = state2.getValue().get().getRandomBase();
        long base3 = state3.getValue().get().getRandomBase();

        assertNotEquals(base1, base2);
        assertNotEquals(base2, base3);
        assertNotEquals(base1, base3);
    }

    // ========== Counter Overflow Tests (Task 4.5) ==========

    /**
     * Test counter overflow detection at 2^31.
     * Requirements: 1.9, 1.10
     */
    @Test
    void testCounterOverflow_At2To31_DetectedAndBlocked() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Initialize state with counter near overflow
        long randomBase = 12345L;
        IVCounterState nearOverflowState = IVCounterState.of(
            dekId, 
            randomBase, 
            Integer.MAX_VALUE, // 2^31 - 1
            Integer.MAX_VALUE
        );
        
        // Persist this state
        storage.persistState(nearOverflowState);
        
        // Create new counter that will load this state
        IVCounterImpl testCounter = new IVCounterImpl(storage);

        // Act - Try to generate IV (should detect overflow)
        Result<IV, IVCounterError> result = testCounter.generateIV(dekId);

        // Assert - Should fail with overflow error
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_OVERFLOW", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("Counter overflow"));
        assertTrue(result.getError().get().getMessage().contains("DEK rotation required"));
    }

    /**
     * Test counter persistence at 1000 increment intervals.
     * Requirements: 1.8
     */
    @Test
    void testCounterPersistence_At1000Intervals() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act - Generate exactly 1000 IVs
        for (int i = 0; i < 1000; i++) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertTrue(result.isSuccess(), "Failed at iteration " + i);
        }

        // Assert - State should be persisted at 1000
        Result<IVCounterState, IVCounterError> loadResult = storage.loadState(dekId);
        assertTrue(loadResult.isSuccess());
        IVCounterState state = loadResult.getValue().get();
        assertEquals(1000, state.getCounter());
        assertEquals(1000, state.getLastPersisted());

        // Act - Generate 1000 more IVs
        for (int i = 0; i < 1000; i++) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertTrue(result.isSuccess(), "Failed at iteration " + (1000 + i));
        }

        // Assert - State should be persisted at 2000
        loadResult = storage.loadState(dekId);
        assertTrue(loadResult.isSuccess());
        state = loadResult.getValue().get();
        assertEquals(2000, state.getCounter());
        assertEquals(2000, state.getLastPersisted());
    }

    /**
     * Test counter state recovery after restart.
     * Requirements: 1.8
     */
    @Test
    void testCounterStateRecovery_AfterRestart() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Generate 2500 IVs (will persist at 1000 and 2000)
        for (int i = 0; i < 2500; i++) {
            ivCounter.generateIV(dekId);
        }

        // Get the random base before restart
        Result<IVCounterState, IVCounterError> beforeState = ivCounter.loadState(dekId);
        assertTrue(beforeState.isSuccess());
        long originalRandomBase = beforeState.getValue().get().getRandomBase();

        // Simulate restart by creating new counter instance
        IVCounterImpl newCounter = new IVCounterImpl(storage);

        // Act - Load state after restart
        Result<IVCounterState, IVCounterError> afterState = newCounter.loadState(dekId);

        // Assert - State should be recovered from last persistence (2000)
        assertTrue(afterState.isSuccess());
        IVCounterState recovered = afterState.getValue().get();
        assertEquals(2000, recovered.getCounter(), 
            "Counter should be recovered from last persisted value");
        assertEquals(2000, recovered.getLastPersisted());
        assertEquals(originalRandomBase, recovered.getRandomBase(), 
            "Random base should be preserved across restart");

        // Act - Generate more IVs after restart
        Result<IV, IVCounterError> ivResult = newCounter.generateIV(dekId);
        assertTrue(ivResult.isSuccess());

        // Assert - Counter should continue from 2000
        Result<IVCounterState, IVCounterError> continuedState = newCounter.loadState(dekId);
        assertTrue(continuedState.isSuccess());
        assertEquals(2001, continuedState.getValue().get().getCounter());
    }

    /**
     * Test that counter doesn't persist between 1000 intervals.
     * Requirements: 1.8
     */
    @Test
    void testCounterPersistence_NotBetweenIntervals() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act - Generate 500 IVs (not at persistence interval)
        for (int i = 0; i < 500; i++) {
            ivCounter.generateIV(dekId);
        }

        // Assert - State in storage should still be at initial state (0)
        // because we haven't hit the 1000 interval yet
        Result<IVCounterState, IVCounterError> loadResult = storage.loadState(dekId);
        assertTrue(loadResult.isSuccess());
        IVCounterState state = loadResult.getValue().get();
        assertEquals(0, state.getCounter(), 
            "Counter in storage should be 0 before first persistence interval");
        assertEquals(0, state.getLastPersisted());
    }

    /**
     * Test overflow detection prevents further IV generation.
     * Requirements: 1.10
     */
    @Test
    void testOverflowDetection_PreventsEncryption() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Set counter to overflow threshold
        IVCounterState overflowState = IVCounterState.of(
            dekId, 
            999L, 
            Integer.MAX_VALUE, 
            Integer.MAX_VALUE
        );
        storage.persistState(overflowState);
        
        IVCounterImpl testCounter = new IVCounterImpl(storage);

        // Act - Try to generate multiple IVs
        Result<IV, IVCounterError> result1 = testCounter.generateIV(dekId);
        Result<IV, IVCounterError> result2 = testCounter.generateIV(dekId);
        Result<IV, IVCounterError> result3 = testCounter.generateIV(dekId);

        // Assert - All should fail with overflow error
        assertTrue(result1.isFailure());
        assertEquals("IV_COUNTER_OVERFLOW", result1.getError().get().getCode());
        
        assertTrue(result2.isFailure());
        assertEquals("IV_COUNTER_OVERFLOW", result2.getError().get().getCode());
        
        assertTrue(result3.isFailure());
        assertEquals("IV_COUNTER_OVERFLOW", result3.getError().get().getCode());
    }

    /**
     * Test counter just before overflow threshold.
     * Requirements: 1.9
     */
    @Test
    void testCounter_JustBeforeOverflow_StillWorks() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        
        // Set counter to 2 below overflow threshold
        IVCounterState nearOverflowState = IVCounterState.of(
            dekId, 
            777L, 
            Integer.MAX_VALUE - 2, 
            Integer.MAX_VALUE - 2
        );
        storage.persistState(nearOverflowState);
        
        IVCounterImpl testCounter = new IVCounterImpl(storage);

        // Act - Generate 2 IVs (should succeed)
        Result<IV, IVCounterError> result1 = testCounter.generateIV(dekId);
        Result<IV, IVCounterError> result2 = testCounter.generateIV(dekId);

        // Assert - Both should succeed
        assertTrue(result1.isSuccess());
        assertTrue(result2.isSuccess());

        // Act - Try to generate one more (should fail)
        Result<IV, IVCounterError> result3 = testCounter.generateIV(dekId);

        // Assert - Should fail with overflow
        assertTrue(result3.isFailure());
        assertEquals("IV_COUNTER_OVERFLOW", result3.getError().get().getCode());
    }

    /**
     * Test that persistence happens exactly at multiples of 1000.
     * Requirements: 1.8
     */
    @Test
    void testPersistence_ExactlyAtMultiplesOf1000() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Test at 1000
        for (int i = 0; i < 1000; i++) {
            ivCounter.generateIV(dekId);
        }
        Result<IVCounterState, IVCounterError> state1 = storage.loadState(dekId);
        assertTrue(state1.isSuccess());
        assertEquals(1000, state1.getValue().get().getLastPersisted());

        // Test at 2000
        for (int i = 0; i < 1000; i++) {
            ivCounter.generateIV(dekId);
        }
        Result<IVCounterState, IVCounterError> state2 = storage.loadState(dekId);
        assertTrue(state2.isSuccess());
        assertEquals(2000, state2.getValue().get().getLastPersisted());

        // Test at 3000
        for (int i = 0; i < 1000; i++) {
            ivCounter.generateIV(dekId);
        }
        Result<IVCounterState, IVCounterError> state3 = storage.loadState(dekId);
        assertTrue(state3.isSuccess());
        assertEquals(3000, state3.getValue().get().getLastPersisted());
    }
}
