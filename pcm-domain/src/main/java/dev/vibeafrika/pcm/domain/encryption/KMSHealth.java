package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;

/**
 * Value object representing the health status of a KMS (Key Management System).
 * 
 * <p>Used for circuit breaker health checks, monitoring, and failover detection.
 */
public final class KMSHealth {
    
    private final boolean available;
    private final String status;
    private final Instant timestamp;
    private final Long latencyMs;
    private final String message;
    
    private KMSHealth(boolean available, String status, Instant timestamp, Long latencyMs, String message) {
        this.available = available;
        this.status = status;
        this.timestamp = timestamp;
        this.latencyMs = latencyMs;
        this.message = message;
    }
    
    /**
     * Creates a healthy KMS status.
     * 
     * @param latencyMs the latency of the health check in milliseconds
     * @return a healthy KMSHealth instance
     */
    public static KMSHealth healthy(long latencyMs) {
        return new KMSHealth(true, "HEALTHY", Instant.now(), latencyMs, "KMS is available");
    }
    
    /**
     * Creates an unhealthy KMS status.
     * 
     * @param message the error message describing why the KMS is unhealthy
     * @return an unhealthy KMSHealth instance
     */
    public static KMSHealth unhealthy(String message) {
        return new KMSHealth(false, "UNHEALTHY", Instant.now(), null, message);
    }
    
    /**
     * Creates a degraded KMS status (available but with issues).
     * 
     * @param latencyMs the latency of the health check in milliseconds
     * @param message the message describing the degradation
     * @return a degraded KMSHealth instance
     */
    public static KMSHealth degraded(long latencyMs, String message) {
        return new KMSHealth(true, "DEGRADED", Instant.now(), latencyMs, message);
    }
    
    /**
     * Returns true if the KMS is available (healthy or degraded).
     */
    public boolean isAvailable() {
        return available;
    }
    
    /**
     * Returns the health status (HEALTHY, UNHEALTHY, or DEGRADED).
     */
    public String getStatus() {
        return status;
    }
    
    /**
     * Returns the timestamp when the health check was performed.
     */
    public Instant getTimestamp() {
        return timestamp;
    }
    
    /**
     * Returns the latency of the health check in milliseconds, or null if unavailable.
     */
    public Long getLatencyMs() {
        return latencyMs;
    }
    
    /**
     * Returns a message describing the health status.
     */
    public String getMessage() {
        return message;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KMSHealth that = (KMSHealth) o;
        return available == that.available &&
               Objects.equals(status, that.status) &&
               Objects.equals(timestamp, that.timestamp) &&
               Objects.equals(latencyMs, that.latencyMs) &&
               Objects.equals(message, that.message);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(available, status, timestamp, latencyMs, message);
    }
    
    @Override
    public String toString() {
        return "KMSHealth{" +
               "available=" + available +
               ", status='" + status + '\'' +
               ", timestamp=" + timestamp +
               ", latencyMs=" + latencyMs +
               ", message='" + message + '\'' +
               '}';
    }
}
