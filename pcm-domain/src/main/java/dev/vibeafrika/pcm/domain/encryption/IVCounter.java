package dev.vibeafrika.pcm.domain.encryption;

import java.util.UUID;

/**
 * Interface for counter-based IV generation with persistence.
 * 
 * The IVCounter manages monotonically increasing counters per DEK, combining
 * a 64-bit random base with a 32-bit counter to generate unique 96-bit IVs.
 * 
 * Key responsibilities:
 * - Generate unique IVs for each encryption operation
 * - Persist counter state every 1000 increments for durability
 * - Detect counter overflow and trigger DEK rotation at 2^31
 * - Maintain counter state per DEK
 */
public interface IVCounter {
    
    /**
     * Generates a unique 96-bit IV for the specified DEK.
     * 
     * The IV is constructed by combining:
     * - 64-bit random base (generated once per DEK)
     * - 32-bit monotonically increasing counter
     * 
     * Counter state is persisted every 1000 increments to survive restarts.
     * When the counter approaches 2^31, an overflow error is returned to trigger
     * DEK rotation.
     * 
     * @param dekId The UUID of the DEK for which to generate an IV
     * @return Result containing the generated IV or an error
     */
    Result<IV, IVCounterError> generateIV(UUID dekId);
    
    /**
     * Manually persists the counter state for a specific DEK.
     * Normally persistence happens automatically every 1000 increments,
     * but this method allows explicit persistence (e.g., during shutdown).
     * 
     * @param dekId The UUID of the DEK whose state should be persisted
     * @return Result indicating success or failure
     */
    Result<Unit, IVCounterError> persistState(UUID dekId);
    
    /**
     * Loads the counter state for a specific DEK from storage.
     * If no state exists, initializes a new state with a random base.
     * 
     * @param dekId The UUID of the DEK whose state should be loaded
     * @return Result containing the loaded or initialized state
     */
    Result<IVCounterState, IVCounterError> loadState(UUID dekId);
    
    /**
     * Resets the counter state for a specific DEK.
     * Used during DEK rotation to start fresh with a new DEK.
     * 
     * @param dekId The UUID of the DEK whose state should be reset
     * @return Result indicating success or failure
     */
    Result<Unit, IVCounterError> resetState(UUID dekId);
}
