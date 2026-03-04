package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.IVCounterError;
import dev.vibeafrika.pcm.domain.encryption.IVCounterState;
import dev.vibeafrika.pcm.domain.encryption.IVCounterStorage;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.Unit;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of IVCounterStorage for testing and development.
 * For production use, implement a database-backed storage.
 */
public class InMemoryIVCounterStorage implements IVCounterStorage {
    
    private final Map<UUID, IVCounterState> storage = new ConcurrentHashMap<>();
    
    @Override
    public Result<Unit, IVCounterError> persistState(IVCounterState state) {
        if (state == null) {
            return Result.failure(IVCounterError.invalidState("State cannot be null"));
        }
        
        try {
            storage.put(state.getDekId(), state);
            return Result.success(Unit.unit());
        } catch (Exception e) {
            return Result.failure(IVCounterError.persistenceFailed(
                state.getDekId().toString(), 
                e.getMessage()
            ));
        }
    }
    
    @Override
    public Result<IVCounterState, IVCounterError> loadState(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        try {
            IVCounterState state = storage.get(dekId);
            if (state == null) {
                return Result.failure(IVCounterError.loadFailed(
                    dekId.toString(), 
                    "No state found for DEK"
                ));
            }
            return Result.success(state);
        } catch (Exception e) {
            return Result.failure(IVCounterError.loadFailed(
                dekId.toString(), 
                e.getMessage()
            ));
        }
    }
    
    @Override
    public Result<Unit, IVCounterError> deleteState(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        try {
            storage.remove(dekId);
            return Result.success(Unit.unit());
        } catch (Exception e) {
            return Result.failure(IVCounterError.persistenceFailed(
                dekId.toString(), 
                "Failed to delete state: " + e.getMessage()
            ));
        }
    }
}
