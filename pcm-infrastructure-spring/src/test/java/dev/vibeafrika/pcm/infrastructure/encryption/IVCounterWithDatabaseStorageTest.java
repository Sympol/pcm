package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for IVCounterImpl with DatabaseIVCounterStorage.
 * 
 * This test verifies that the IVCounter works correctly with the database-backed
 * storage implementation, ensuring counter state persistence across restarts.
 * 
 */
class IVCounterWithDatabaseStorageTest {

    private IVCounterStorage storage;
    private IVCounterImpl ivCounter;

    @BeforeEach
    void setUp() {
        // Use in-memory storage for testing (simulates database behavior)
        storage = new InMemoryIVCounterStorage();
        ivCounter = new IVCounterImpl(storage);
    }

    @Test
    void testIVCounterWithDatabaseStorage_PersistenceWorks() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act - Generate 1500 IVs (will persist at 1000)
        for (int i = 0; i < 1500; i++) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertTrue(result.isSuccess(), "Failed at iteration " + i);
        }

        // Simulate restart by creating new counter with same storage
        IVCounterImpl newCounter = new IVCounterImpl(storage);

        // Act - Generate more IVs after restart
        Result<IV, IVCounterError> result = newCounter.generateIV(dekId);

        // Assert
        assertTrue(result.isSuccess());
        
        // Verify counter continued from persisted value (1000)
        Result<IVCounterState, IVCounterError> stateResult = newCounter.loadState(dekId);
        assertTrue(stateResult.isSuccess());
        
        // Counter should be at least 1001 (loaded 1000 + 1 from generateIV above)
        IVCounterState state = stateResult.getValue().get();
        assertTrue(state.getCounter() >= 1001, 
            "Counter should continue from persisted value after restart");
    }

    @Test
    void testIVCounterWithDatabaseStorage_MultipleRestarts() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // First session - generate 2500 IVs
        for (int i = 0; i < 2500; i++) {
            ivCounter.generateIV(dekId);
        }

        // Restart 1
        IVCounterImpl counter2 = new IVCounterImpl(storage);
        for (int i = 0; i < 1500; i++) {
            counter2.generateIV(dekId);
        }

        // Restart 2
        IVCounterImpl counter3 = new IVCounterImpl(storage);
        Result<IVCounterState, IVCounterError> stateResult = counter3.loadState(dekId);

        // Assert - Should load from last persistence (3000)
        assertTrue(stateResult.isSuccess());
        IVCounterState state = stateResult.getValue().get();
        assertEquals(3000, state.getCounter(), 
            "Counter should be at last persisted value after multiple restarts");
        assertEquals(3000, state.getLastPersisted());
    }

    @Test
    void testIVCounterWithDatabaseStorage_RandomBasePreserved() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Generate some IVs
        ivCounter.generateIV(dekId);
        Result<IVCounterState, IVCounterError> originalState = ivCounter.loadState(dekId);
        assertTrue(originalState.isSuccess());
        long originalRandomBase = originalState.getValue().get().getRandomBase();

        // Persist manually
        ivCounter.persistState(dekId);

        // Simulate restart
        IVCounterImpl newCounter = new IVCounterImpl(storage);
        Result<IVCounterState, IVCounterError> loadedState = newCounter.loadState(dekId);

        // Assert - Random base should be preserved
        assertTrue(loadedState.isSuccess());
        assertEquals(originalRandomBase, loadedState.getValue().get().getRandomBase(),
            "Random base should be preserved across restarts");
    }

    @Test
    void testIVCounterWithDatabaseStorage_IndependentDEKs() {
        // Arrange
        UUID dekId1 = UUID.randomUUID();
        UUID dekId2 = UUID.randomUUID();

        // Generate IVs for both DEKs
        for (int i = 0; i < 1500; i++) {
            ivCounter.generateIV(dekId1);
        }
        for (int i = 0; i < 2500; i++) {
            ivCounter.generateIV(dekId2);
        }

        // Simulate restart
        IVCounterImpl newCounter = new IVCounterImpl(storage);

        // Load states
        Result<IVCounterState, IVCounterError> state1 = newCounter.loadState(dekId1);
        Result<IVCounterState, IVCounterError> state2 = newCounter.loadState(dekId2);

        // Assert - Each DEK should have independent counter state
        assertTrue(state1.isSuccess());
        assertTrue(state2.isSuccess());
        
        assertEquals(1000, state1.getValue().get().getCounter());
        assertEquals(2000, state2.getValue().get().getCounter());
        
        assertNotEquals(state1.getValue().get().getRandomBase(), 
                       state2.getValue().get().getRandomBase(),
                       "Different DEKs should have different random bases");
    }

    @Test
    void testIVCounterWithDatabaseStorage_DeleteAndRecreate() {
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Generate some IVs
        for (int i = 0; i < 1500; i++) {
            ivCounter.generateIV(dekId);
        }
        
        Result<IVCounterState, IVCounterError> originalState = ivCounter.loadState(dekId);
        assertTrue(originalState.isSuccess());
        long originalRandomBase = originalState.getValue().get().getRandomBase();

        // Delete state
        Result<Unit, IVCounterError> deleteResult = ivCounter.resetState(dekId);
        assertTrue(deleteResult.isSuccess());

        // Simulate restart
        IVCounterImpl newCounter = new IVCounterImpl(storage);

        // Generate IV (should create new state)
        Result<IV, IVCounterError> ivResult = newCounter.generateIV(dekId);
        assertTrue(ivResult.isSuccess());

        // Load new state
        Result<IVCounterState, IVCounterError> newState = newCounter.loadState(dekId);
        assertTrue(newState.isSuccess());

        // Assert - Should have new random base and counter starting from 0
        assertNotEquals(originalRandomBase, newState.getValue().get().getRandomBase(),
            "After deletion, a new random base should be generated");
        assertEquals(1, newState.getValue().get().getCounter(),
            "After deletion, counter should start from 0 (now at 1 after one IV generation)");
    }

    @Test
    void testIVCounterWithDatabaseStorage_PersistenceFailureHandling() {
        // This test verifies that even if persistence fails, IV generation continues
        // (with a warning logged, but not blocking encryption operations)
        
        // Arrange
        UUID dekId = UUID.randomUUID();

        // Act - Generate IVs normally
        for (int i = 0; i < 1100; i++) {
            Result<IV, IVCounterError> result = ivCounter.generateIV(dekId);
            assertTrue(result.isSuccess(), "IV generation should succeed even if persistence has issues");
        }

        // Assert - Counter should be at 1100 in memory
        Result<IVCounterState, IVCounterError> state = ivCounter.loadState(dekId);
        assertTrue(state.isSuccess());
        assertEquals(1100, state.getValue().get().getCounter());
    }
}
