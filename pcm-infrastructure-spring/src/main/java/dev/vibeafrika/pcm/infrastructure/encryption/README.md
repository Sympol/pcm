# IV Counter Storage Implementation

## Overview

This directory contains the implementation of IV (Initialization Vector) counter storage for the PII encryption feature. The counter-based IV generation ensures unique IVs for each encryption operation while maintaining durability across application restarts.

## Components

### Domain Layer (pcm-domain)

- **IVCounterStorage** (interface): Defines the contract for persisting and loading IV counter state
- **IVCounterState**: Value object representing the counter state (DEK ID, random base, counter, last persisted)
- **IVCounter** (interface): Defines the contract for IV generation with counter management

### Infrastructure Layer (pcm-infrastructure-spring)

#### Storage Implementations

1. **InMemoryIVCounterStorage**
   - In-memory implementation using ConcurrentHashMap
   - Suitable for testing and development
   - Does not survive application restarts
   - Thread-safe

2. **DatabaseIVCounterStorage** ✨ NEW
   - Database-backed implementation using Spring Data JPA
   - Provides durable storage that survives application restarts
   - Uses optimistic locking (@Version) for concurrency control
   - Suitable for production use
   - Thread-safe via database transaction isolation

#### Supporting Components

- **IVCounterStateEntity**: JPA entity for persisting counter state
- **IVCounterStateRepository**: Spring Data JPA repository for database access
- **IVCounterImpl**: Implementation of IVCounter that uses IVCounterStorage

## Database Schema

```sql
CREATE TABLE encryption_iv_counter_state (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    dek_id BINARY(16) NOT NULL UNIQUE,
    random_base BIGINT NOT NULL,
    counter INT NOT NULL,
    last_persisted INT NOT NULL,
    version BIGINT,
    INDEX idx_iv_counter_dek_id (dek_id)
);
```

## Usage

### Configuration

In your Spring configuration, choose the appropriate storage implementation:

```java
@Configuration
public class EncryptionConfiguration {
    
    // For production (database-backed)
    @Bean
    @Primary
    public IVCounterStorage ivCounterStorage(IVCounterStateRepository repository) {
        return new DatabaseIVCounterStorage(repository);
    }
    
    // For testing (in-memory)
    @Bean
    @Profile("test")
    public IVCounterStorage testIVCounterStorage() {
        return new InMemoryIVCounterStorage();
    }
    
    @Bean
    public IVCounter ivCounter(IVCounterStorage storage) {
        return new IVCounterImpl(storage);
    }
}
```

### Counter Persistence Behavior

The counter state is persisted according to requirement 1.8:

- **Automatic persistence**: Every 1000 increments
- **Manual persistence**: Via `persistState(dekId)` method (e.g., during shutdown)
- **Overflow detection**: At 2^31 operations, triggers DEK rotation requirement

### Example Flow

```java
// Generate IV (counter increments automatically)
Result<IV, IVCounterError> ivResult = ivCounter.generateIV(dekId);

// After 1000 IVs, state is automatically persisted to database
// On application restart, counter continues from last persisted value

// Manual persistence (e.g., during graceful shutdown)
ivCounter.persistState(dekId);
```

## Thread Safety

- **InMemoryIVCounterStorage**: Uses ConcurrentHashMap for thread-safe operations
- **DatabaseIVCounterStorage**: Uses database transaction isolation and optimistic locking (@Version field)
- **IVCounterImpl**: Uses ConcurrentHashMap for in-memory cache, delegates persistence to storage

## Testing

### Unit Tests

- **DatabaseIVCounterStorageTest**: Tests database storage with mocked repository
- **IVCounterImplTest**: Tests IV generation, persistence, and overflow detection
- **IVCounterWithDatabaseStorageTest**: Integration tests for IVCounter with database storage

### Running Tests

```bash
# Run all IV counter tests
mvn test -pl pcm-infrastructure-spring -Dtest="*IVCounter*"

# Run specific test
mvn test -pl pcm-infrastructure-spring -Dtest=DatabaseIVCounterStorageTest
```

## Requirements Satisfied

- Counter state persisted every 1000 increments
- Counter overflow detection at 2^31
- Overflow prevents encryption until DEK rotation

## Migration from In-Memory to Database

If you're currently using InMemoryIVCounterStorage and want to migrate to DatabaseIVCounterStorage:

1. Ensure database schema is created (via Flyway/Liquibase migration)
2. Update Spring configuration to use DatabaseIVCounterStorage
3. Restart application - new counter states will be persisted to database
4. Existing in-memory states will be lost (counters reset to 0 for each DEK)

**Note**: For production systems, it's recommended to start with DatabaseIVCounterStorage from the beginning to avoid counter resets.

## Performance Considerations

- **Cache-first approach**: IVCounterImpl caches state in memory, reducing database queries
- **Batch persistence**: Only persists every 1000 increments, not on every IV generation
- **Optimistic locking**: Prevents concurrent modification issues without pessimistic locks
- **Index on dek_id**: Ensures fast lookups by DEK identifier

## Future Enhancements

- **Distributed counter**: For multi-instance deployments, consider distributed counter coordination
- **Metrics**: Add metrics for counter persistence failures, overflow events, etc.
- **Backup/restore**: Implement backup procedures for counter state
