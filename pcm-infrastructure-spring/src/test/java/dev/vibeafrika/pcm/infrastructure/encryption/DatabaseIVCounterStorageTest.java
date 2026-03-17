package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.IVCounterError;
import dev.vibeafrika.pcm.domain.encryption.IVCounterState;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.Unit;
import dev.vibeafrika.pcm.infrastructure.encryption.entity.IVCounterStateEntity;
import dev.vibeafrika.pcm.infrastructure.encryption.repository.IVCounterStateRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for DatabaseIVCounterStorage.
 * 
 * Tests database-backed persistence of IV counter state using mocked repository.
 */
@ExtendWith(MockitoExtension.class)
class DatabaseIVCounterStorageTest {

    @Mock
    private IVCounterStateRepository repository;

    private DatabaseIVCounterStorage storage;

    @BeforeEach
    void setUp() {
        storage = new DatabaseIVCounterStorage(repository);
    }

    @Test
    void testPersistState_NewState_Success() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        IVCounterState state = IVCounterState.of(dekId, 12345L, 100, 0);
        
        when(repository.findByDekId(dekId)).thenReturn(Optional.empty());
        when(repository.save(any(IVCounterStateEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        Result<Unit, IVCounterError> result = storage.persistState(state);

        // Assert
        assertTrue(result.isSuccess());
        verify(repository).findByDekId(dekId);
        verify(repository).save(any(IVCounterStateEntity.class));
    }

    @Test
    void testPersistState_UpdateExisting_Success() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        IVCounterState state = IVCounterState.of(dekId, 12345L, 1000, 1000);
        
        IVCounterStateEntity existingEntity = new IVCounterStateEntity(dekId, 12345L, 500, 0);
        when(repository.findByDekId(dekId)).thenReturn(Optional.of(existingEntity));
        when(repository.save(any(IVCounterStateEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        Result<Unit, IVCounterError> result = storage.persistState(state);

        // Assert
        assertTrue(result.isSuccess());
        verify(repository).findByDekId(dekId);
        verify(repository).save(any(IVCounterStateEntity.class));
        
        // Verify entity was updated
        assertEquals(1000, existingEntity.getCounter());
        assertEquals(1000, existingEntity.getLastPersisted());
    }

    @Test
    void testPersistState_NullState_Failure() {
        // Act
        Result<Unit, IVCounterError> result = storage.persistState(null);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("cannot be null"));
        verifyNoInteractions(repository);
    }

    @Test
    void testPersistState_RepositoryException_Failure() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        IVCounterState state = IVCounterState.of(dekId, 12345L, 100, 0);
        
        when(repository.findByDekId(dekId)).thenThrow(new RuntimeException("Database error"));

        // Act
        Result<Unit, IVCounterError> result = storage.persistState(state);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_PERSISTENCE_FAILED", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("Failed to persist"));
        assertTrue(result.getError().get().getMessage().contains("Database error"));
    }

    @Test
    void testLoadState_Exists_Success() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        IVCounterStateEntity entity = new IVCounterStateEntity(dekId, 12345L, 1000, 1000);
        
        when(repository.findByDekId(dekId)).thenReturn(Optional.of(entity));

        // Act
        Result<IVCounterState, IVCounterError> result = storage.loadState(dekId);

        // Assert
        assertTrue(result.isSuccess());
        IVCounterState state = result.getValue().get();
        assertEquals(dekId, state.getDekId());
        assertEquals(12345L, state.getRandomBase());
        assertEquals(1000, state.getCounter());
        assertEquals(1000, state.getLastPersisted());
        verify(repository).findByDekId(dekId);
    }

    @Test
    void testLoadState_NotFound_Failure() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        when(repository.findByDekId(dekId)).thenReturn(Optional.empty());

        // Act
        Result<IVCounterState, IVCounterError> result = storage.loadState(dekId);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_LOAD_FAILED", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("No state found"));
        verify(repository).findByDekId(dekId);
    }

    @Test
    void testLoadState_NullDekId_Failure() {
        // Act
        Result<IVCounterState, IVCounterError> result = storage.loadState(null);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("cannot be null"));
        verifyNoInteractions(repository);
    }

    @Test
    void testLoadState_RepositoryException_Failure() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        when(repository.findByDekId(dekId)).thenThrow(new RuntimeException("Database connection lost"));

        // Act
        Result<IVCounterState, IVCounterError> result = storage.loadState(dekId);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_LOAD_FAILED", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("Failed to load"));
        assertTrue(result.getError().get().getMessage().contains("Database connection lost"));
    }

    @Test
    void testDeleteState_Success() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        doNothing().when(repository).deleteByDekId(dekId);

        // Act
        Result<Unit, IVCounterError> result = storage.deleteState(dekId);

        // Assert
        assertTrue(result.isSuccess());
        verify(repository).deleteByDekId(dekId);
    }

    @Test
    void testDeleteState_NullDekId_Failure() {
        // Act
        Result<Unit, IVCounterError> result = storage.deleteState(null);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_INVALID_STATE", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("cannot be null"));
        verifyNoInteractions(repository);
    }

    @Test
    void testDeleteState_RepositoryException_Failure() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        doThrow(new RuntimeException("Delete failed")).when(repository).deleteByDekId(dekId);

        // Act
        Result<Unit, IVCounterError> result = storage.deleteState(dekId);

        // Assert
        assertTrue(result.isFailure());
        assertEquals("IV_COUNTER_PERSISTENCE_FAILED", result.getError().get().getCode());
        assertTrue(result.getError().get().getMessage().contains("Failed to delete"));
        assertTrue(result.getError().get().getMessage().contains("Delete failed"));
    }

    @Test
    void testPersistState_PreservesRandomBase() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        long randomBase = 9876543210L;
        IVCounterState state = IVCounterState.of(dekId, randomBase, 2000, 2000);
        
        when(repository.findByDekId(dekId)).thenReturn(Optional.empty());
        when(repository.save(any(IVCounterStateEntity.class))).thenAnswer(invocation -> {
            IVCounterStateEntity saved = invocation.getArgument(0);
            assertEquals(randomBase, saved.getRandomBase());
            return saved;
        });

        // Act
        Result<Unit, IVCounterError> result = storage.persistState(state);

        // Assert
        assertTrue(result.isSuccess());
        verify(repository).save(any(IVCounterStateEntity.class));
    }

    @Test
    void testPersistAndLoad_RoundTrip() {
        // Arrange
        UUID dekId = UUID.randomUUID();
        long randomBase = 123456789L;
        int counter = 5000;
        int lastPersisted = 5000;
        IVCounterState originalState = IVCounterState.of(dekId, randomBase, counter, lastPersisted);
        
        IVCounterStateEntity savedEntity = new IVCounterStateEntity(dekId, randomBase, counter, lastPersisted);
        
        when(repository.findByDekId(dekId))
            .thenReturn(Optional.empty())
            .thenReturn(Optional.of(savedEntity));
        when(repository.save(any(IVCounterStateEntity.class))).thenReturn(savedEntity);

        // Act - Persist
        Result<Unit, IVCounterError> persistResult = storage.persistState(originalState);
        
        // Act - Load
        Result<IVCounterState, IVCounterError> loadResult = storage.loadState(dekId);

        // Assert
        assertTrue(persistResult.isSuccess());
        assertTrue(loadResult.isSuccess());
        
        IVCounterState loadedState = loadResult.getValue().get();
        assertEquals(originalState.getDekId(), loadedState.getDekId());
        assertEquals(originalState.getRandomBase(), loadedState.getRandomBase());
        assertEquals(originalState.getCounter(), loadedState.getCounter());
        assertEquals(originalState.getLastPersisted(), loadedState.getLastPersisted());
    }

    @Test
    void testMultipleDEKs_IndependentStorage() {
        // Arrange
        UUID dekId1 = UUID.randomUUID();
        UUID dekId2 = UUID.randomUUID();
        
        IVCounterState state1 = IVCounterState.of(dekId1, 111L, 100, 0);
        IVCounterState state2 = IVCounterState.of(dekId2, 222L, 200, 0);
        
        IVCounterStateEntity entity1 = new IVCounterStateEntity(dekId1, 111L, 100, 0);
        IVCounterStateEntity entity2 = new IVCounterStateEntity(dekId2, 222L, 200, 0);
        
        when(repository.findByDekId(dekId1)).thenReturn(Optional.empty()).thenReturn(Optional.of(entity1));
        when(repository.findByDekId(dekId2)).thenReturn(Optional.empty()).thenReturn(Optional.of(entity2));
        when(repository.save(any(IVCounterStateEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // Act - Persist both
        Result<Unit, IVCounterError> persist1 = storage.persistState(state1);
        Result<Unit, IVCounterError> persist2 = storage.persistState(state2);
        
        // Act - Load both
        Result<IVCounterState, IVCounterError> load1 = storage.loadState(dekId1);
        Result<IVCounterState, IVCounterError> load2 = storage.loadState(dekId2);

        // Assert
        assertTrue(persist1.isSuccess());
        assertTrue(persist2.isSuccess());
        assertTrue(load1.isSuccess());
        assertTrue(load2.isSuccess());
        
        assertEquals(111L, load1.getValue().get().getRandomBase());
        assertEquals(100, load1.getValue().get().getCounter());
        
        assertEquals(222L, load2.getValue().get().getRandomBase());
        assertEquals(200, load2.getValue().get().getCounter());
    }
}
