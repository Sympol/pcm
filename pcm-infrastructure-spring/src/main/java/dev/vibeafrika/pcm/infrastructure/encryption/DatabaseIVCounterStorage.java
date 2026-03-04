package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.entity.IVCounterStateEntity;
import dev.vibeafrika.pcm.infrastructure.encryption.repository.IVCounterStateRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Database-backed implementation of IVCounterStorage using Spring Data JPA.
 * 
 * This implementation provides durable storage for IV counter state,
 * ensuring counter values survive application restarts. The counter state
 * is persisted every 1000 increments as specified in requirement 1.8.
 * 
 * Thread-safety is provided by the database transaction isolation level
 * and optimistic locking via the @Version field.
 */
@Component
public class DatabaseIVCounterStorage implements IVCounterStorage {
    
    private final IVCounterStateRepository repository;
    
    public DatabaseIVCounterStorage(IVCounterStateRepository repository) {
        this.repository = repository;
    }
    
    @Override
    @Transactional
    public Result<Unit, IVCounterError> persistState(IVCounterState state) {
        if (state == null) {
            return Result.failure(IVCounterError.invalidState("State cannot be null"));
        }
        
        try {
            Optional<IVCounterStateEntity> existingEntity = repository.findByDekId(state.getDekId());
            
            IVCounterStateEntity entity;
            if (existingEntity.isPresent()) {
                // Update existing entity
                entity = existingEntity.get();
                entity.setRandomBase(state.getRandomBase());
                entity.setCounter(state.getCounter());
                entity.setLastPersisted(state.getLastPersisted());
            } else {
                // Create new entity
                entity = new IVCounterStateEntity(
                    state.getDekId(),
                    state.getRandomBase(),
                    state.getCounter(),
                    state.getLastPersisted()
                );
            }
            
            repository.save(entity);
            return Result.success(Unit.unit());
            
        } catch (Exception e) {
            return Result.failure(IVCounterError.persistenceFailed(
                state.getDekId().toString(),
                "Failed to persist counter state: " + e.getMessage()
            ));
        }
    }
    
    @Override
    @Transactional(readOnly = true)
    public Result<IVCounterState, IVCounterError> loadState(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        try {
            Optional<IVCounterStateEntity> entityOpt = repository.findByDekId(dekId);
            
            if (entityOpt.isEmpty()) {
                return Result.failure(IVCounterError.loadFailed(
                    dekId.toString(),
                    "No state found for DEK"
                ));
            }
            
            IVCounterStateEntity entity = entityOpt.get();
            IVCounterState state = IVCounterState.of(
                entity.getDekId(),
                entity.getRandomBase(),
                entity.getCounter(),
                entity.getLastPersisted()
            );
            
            return Result.success(state);
            
        } catch (Exception e) {
            return Result.failure(IVCounterError.loadFailed(
                dekId.toString(),
                "Failed to load counter state: " + e.getMessage()
            ));
        }
    }
    
    @Override
    @Transactional
    public Result<Unit, IVCounterError> deleteState(UUID dekId) {
        if (dekId == null) {
            return Result.failure(IVCounterError.invalidState("DEK ID cannot be null"));
        }
        
        try {
            repository.deleteByDekId(dekId);
            return Result.success(Unit.unit());
            
        } catch (Exception e) {
            return Result.failure(IVCounterError.persistenceFailed(
                dekId.toString(),
                "Failed to delete counter state: " + e.getMessage()
            ));
        }
    }
}
