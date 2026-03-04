package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;
import java.util.UUID;

/**
 * Represents the state of an IV counter for a specific DEK.
 * Contains the random base, current counter value, and last persisted counter value.
 */
public final class IVCounterState {
    private final UUID dekId;
    private final long randomBase; // 64 bits
    private final int counter;     // 32 bits
    private final int lastPersisted;

    private IVCounterState(UUID dekId, long randomBase, int counter, int lastPersisted) {
        this.dekId = dekId;
        this.randomBase = randomBase;
        this.counter = counter;
        this.lastPersisted = lastPersisted;
    }

    public static IVCounterState of(UUID dekId, long randomBase, int counter, int lastPersisted) {
        Objects.requireNonNull(dekId, "DEK ID cannot be null");
        return new IVCounterState(dekId, randomBase, counter, lastPersisted);
    }

    /**
     * Creates a new initial state with a random base and counter starting at 0.
     */
    public static IVCounterState initial(UUID dekId, long randomBase) {
        Objects.requireNonNull(dekId, "DEK ID cannot be null");
        return new IVCounterState(dekId, randomBase, 0, 0);
    }

    /**
     * Creates a new state with an incremented counter.
     */
    public IVCounterState withIncrementedCounter() {
        return new IVCounterState(dekId, randomBase, counter + 1, lastPersisted);
    }

    /**
     * Creates a new state marking the current counter as persisted.
     */
    public IVCounterState withPersisted() {
        return new IVCounterState(dekId, randomBase, counter, counter);
    }

    public UUID getDekId() {
        return dekId;
    }

    public long getRandomBase() {
        return randomBase;
    }

    public int getCounter() {
        return counter;
    }

    public int getLastPersisted() {
        return lastPersisted;
    }

    /**
     * Checks if the counter is approaching overflow (at 2^31).
     * We trigger rotation at 2^31 to stay well below 2^32.
     */
    public boolean isOverflowImminent() {
        return counter >= Integer.MAX_VALUE; // 2^31 - 1
    }

    /**
     * Checks if persistence is needed (every 1000 increments).
     */
    public boolean needsPersistence() {
        return counter > 0 && counter % 1000 == 0 && counter != lastPersisted;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IVCounterState that = (IVCounterState) o;
        return randomBase == that.randomBase &&
               counter == that.counter &&
               lastPersisted == that.lastPersisted &&
               Objects.equals(dekId, that.dekId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(dekId, randomBase, counter, lastPersisted);
    }

    @Override
    public String toString() {
        return "IVCounterState{" +
               "dekId=" + dekId +
               ", randomBase=" + randomBase +
               ", counter=" + counter +
               ", lastPersisted=" + lastPersisted +
               '}';
    }
}
