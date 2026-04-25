package dev.vibeafrika.pcm.infrastructure.encryption.entity;

import jakarta.persistence.*;
import java.util.UUID;

/**
 * JPA entity for persisting IV counter state.
 * 
 * This entity stores the counter state for each DEK to ensure IV uniqueness
 * across application restarts. The counter is persisted every 1000 increments.
 */
@Entity
@Table(name = "encryption_iv_counter_state", indexes = {
    @Index(name = "idx_iv_counter_dek_id", columnList = "dek_id", unique = true)
})
public class IVCounterStateEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    
    @Column(name = "dek_id", nullable = false, unique = true, columnDefinition = "BINARY(16)")
    private UUID dekId;
    
    @Column(name = "random_base", nullable = false)
    private long randomBase;
    
    @Column(name = "counter", nullable = false)
    private int counter;
    
    @Column(name = "last_persisted", nullable = false)
    private int lastPersisted;
    
    @Version
    @Column(name = "version")
    private Long version;
    
    protected IVCounterStateEntity() {
        // JPA requires a no-arg constructor
    }
    
    public IVCounterStateEntity(UUID dekId, long randomBase, int counter, int lastPersisted) {
        this.dekId = dekId;
        this.randomBase = randomBase;
        this.counter = counter;
        this.lastPersisted = lastPersisted;
    }
    
    public Long getId() {
        return id;
    }
    
    public UUID getDekId() {
        return dekId;
    }
    
    public void setDekId(UUID dekId) {
        this.dekId = dekId;
    }
    
    public long getRandomBase() {
        return randomBase;
    }
    
    public void setRandomBase(long randomBase) {
        this.randomBase = randomBase;
    }
    
    public int getCounter() {
        return counter;
    }
    
    public void setCounter(int counter) {
        this.counter = counter;
    }
    
    public int getLastPersisted() {
        return lastPersisted;
    }
    
    public void setLastPersisted(int lastPersisted) {
        this.lastPersisted = lastPersisted;
    }
    
    public Long getVersion() {
        return version;
    }
}
