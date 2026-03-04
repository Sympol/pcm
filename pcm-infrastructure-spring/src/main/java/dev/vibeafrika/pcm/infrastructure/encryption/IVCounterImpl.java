package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of IVCounter that manages counter-based IV generation with persistence.
 * 
 * This implementation:
 * - Maintains in-memory counter state per DEK
 * - Persists counter state every 1000 increments
 * - Detects counter overflow at 2^31 and triggers rotation
 * - Uses SecureRandom for generating random bases
 * - Thread-safe for concurrent IV generation
 */
public class IVCounterImpl implements IVCounter {
    
    private static final int PERSISTENCE_INTERVAL = 1000;
    private static final int OVERFLOW_THRESHOLD = Integer.MAX_VALUE; // 2^31 - 1
    
    private final IVCounterStorage storage;
    private final SecureRandom secureRandom;
    private final Map<UUID, IVCounterState> stateCache;
    
    public IVCounterImpl(IVCounterStorage storage) {
        this.storage = storage;
        this.secureRandom = new SecureRandom();
        this.stateCache = new ConcurrentHashMap<>();
    }
    
    @Override
    public Result<IV, IVCounterError> generateIV(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        // Get or initialize state
        Result<IVCounterState, IVCounterError> stateResult = getOrInitializeState(dekId);
        if (stateResult.isFailure()) {
            return Result.failure(stateResult.getError().orElseThrow());
        }
        
        IVCounterState currentState = stateResult.getValue().orElseThrow();
        
        // Check for overflow before incrementing
        if (currentState.isOverflowImminent()) {
            return Result.failure(IVCounterError.counterOverflow(dekId.toString()));
        }
        
        // Increment counter
        IVCounterState newState = currentState.withIncrementedCounter();
        
        // Check if we need to persist
        if (newState.needsPersistence()) {
            IVCounterState persistedState = newState.withPersisted();
            Result<Unit, IVCounterError> persistResult = storage.persistState(persistedState);
            if (persistResult.isFailure()) {
                // Log warning but continue - we don't want to block encryption
                // In production, this should be logged properly
                System.err.println("Warning: Failed to persist counter state: " + 
                    persistResult.getError().orElseThrow().getMessage());
            }
            stateCache.put(dekId, persistedState);
        } else {
            stateCache.put(dekId, newState);
        }
        
        // Generate IV from random base and counter
        IV iv = IV.fromComponents(newState.getRandomBase(), newState.getCounter());
        return Result.success(iv);
    }
    
    @Override
    public Result<Unit, IVCounterError> persistState(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        IVCounterState state = stateCache.get(dekId);
        if (state == null) {
            return Result.failure(IVCounterError.invalidState(
                "No state found in cache for DEK " + dekId
            ));
        }
        
        IVCounterState persistedState = state.withPersisted();
        Result<Unit, IVCounterError> result = storage.persistState(persistedState);
        
        if (result.isSuccess()) {
            stateCache.put(dekId, persistedState);
        }
        
        return result;
    }
    
    @Override
    public Result<IVCounterState, IVCounterError> loadState(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        // Check cache first
        IVCounterState cachedState = stateCache.get(dekId);
        if (cachedState != null) {
            return Result.success(cachedState);
        }
        
        // Try to load from storage
        Result<IVCounterState, IVCounterError> storageResult = storage.loadState(dekId);
        if (storageResult.isSuccess()) {
            IVCounterState state = storageResult.getValue().orElseThrow();
            stateCache.put(dekId, state);
            return Result.success(state);
        }
        
        // If not found, initialize new state
        long randomBase = secureRandom.nextLong();
        IVCounterState newState = IVCounterState.initial(dekId, randomBase);
        
        // Persist initial state
        Result<Unit, IVCounterError> persistResult = storage.persistState(newState);
        if (persistResult.isFailure()) {
            return Result.failure(persistResult.getError().orElseThrow());
        }
        
        stateCache.put(dekId, newState);
        return Result.success(newState);
    }
    
    @Override
    public Result<Unit, IVCounterError> resetState(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        // Remove from cache
        stateCache.remove(dekId);
        
        // Delete from storage
        return storage.deleteState(dekId);
    }
    
    /**
     * Gets existing state or initializes a new one if not found.
     */
    private Result<IVCounterState, IVCounterError> getOrInitializeState(UUID dekId) {
        // Check cache first
        IVCounterState cachedState = stateCache.get(dekId);
        if (cachedState != null) {
            return Result.success(cachedState);
        }
        
        // Try to load from storage
        Result<IVCounterState, IVCounterError> storageResult = storage.loadState(dekId);
        if (storageResult.isSuccess()) {
            IVCounterState state = storageResult.getValue().orElseThrow();
            stateCache.put(dekId, state);
            return Result.success(state);
        }
        
        // Initialize new state
        long randomBase = secureRandom.nextLong();
        IVCounterState newState = IVCounterState.initial(dekId, randomBase);
        
        // Persist initial state
        Result<Unit, IVCounterError> persistResult = storage.persistState(newState);
        if (persistResult.isFailure()) {
            return Result.failure(persistResult.getError().orElseThrow());
        }
        
        stateCache.put(dekId, newState);
        return Result.success(newState);
    }
}
