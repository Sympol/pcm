package dev.vibeafrika.pcm.domain.encryption;

/**
 * Unit type for representing "no value" in Result types.
 * Used instead of Void which cannot be instantiated.
 */
public final class Unit {
    private static final Unit INSTANCE = new Unit();
    
    private Unit() {
        // Private constructor
    }
    
    public static Unit unit() {
        return INSTANCE;
    }
    
    @Override
    public String toString() {
        return "()";
    }
}
