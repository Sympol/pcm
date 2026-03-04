package dev.vibeafrika.pcm.domain.encryption;

import java.util.UUID;

/**
 * Interface for persisting and loading IV counter state.
 * Implementations should provide durable storage that survives application restarts.
 */
public interface IVCounterStorage {
    
    /**
     * Persists the counter state for a specific DEK.
     * 
     * @param state The counter state to persist
     * @return Result indicating success or failure
     */
    Result<Unit, IVCounterError> persistState(IVCounterState state);
    
    /**
     * Loads the counter state for a specific DEK.
     * 
     * @param dekId The DEK identifier
     * @return Result containing the loaded state or an error if not found
     */
    Result<IVCounterState, IVCounterError> loadState(UUID dekId);
    
    /**
     * Deletes the counter state for a specific DEK.
     * Used during DEK rotation or deletion.
     * 
     * @param dekId The DEK identifier
     * @return Result indicating success or failure
     */
    Result<Unit, IVCounterError> deleteState(UUID dekId);
}
