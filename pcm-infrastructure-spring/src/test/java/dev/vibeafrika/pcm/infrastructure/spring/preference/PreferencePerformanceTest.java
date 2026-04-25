package dev.vibeafrika.pcm.infrastructure.spring.preference;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Performance baseline tests for the Preference context REST API.
 *
 *
 * Thresholds used:
 * - POST p95 latency < 500ms
 * - GET  p95 latency < 200ms
 * - Throughput > 10 requests/second (sequential GET)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class PreferencePerformanceTest {

    private static final Logger log = LoggerFactory.getLogger(PreferencePerformanceTest.class);

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_perf_test")
            .withUsername("pcm_user")
            .withPassword("pcm_password");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @LocalServerPort
    int port;

    private static final String TENANT_ID = "tenant-perf-test";
    private static final String BASE_PATH = "/api/v1/preferences";

    private static final int WARMUP_REQUESTS = 10;
    private static final int MEASURE_REQUESTS = 50;
    private static final int THROUGHPUT_REQUESTS = 100;

    private static final long POST_P95_THRESHOLD_MS = 500;
    private static final long GET_P95_THRESHOLD_MS = 200;
    private static final double THROUGHPUT_MIN_RPS = 10.0;

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.basePath = "";
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private Map<String, Object> createBody(UUID profileId) {
        return Map.of(
            "tenantId", TENANT_ID,
            "profileId", profileId.toString(),
            "settings", Map.of("theme", "dark", "language", "en")
        );
    }

    /** Creates a preference and returns its ID. */
    private String createPreference() {
        return given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(UUID.randomUUID()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");
    }

    /** Measures elapsed time in ms for a single POST request. */
    private long timePost() {
        long start = System.nanoTime();
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(UUID.randomUUID()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201);
        return (System.nanoTime() - start) / 1_000_000;
    }

    /** Measures elapsed time in ms for a single GET request. */
    private long timeGet(String preferenceId) {
        long start = System.nanoTime();
        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + preferenceId)
        .then()
            .statusCode(200);
        return (System.nanoTime() - start) / 1_000_000;
    }

    /** Returns the p-th percentile (0–100) from a sorted list of longs. */
    private long percentile(List<Long> sortedSamples, int p) {
        if (sortedSamples.isEmpty()) return 0;
        int index = (int) Math.ceil(p / 100.0 * sortedSamples.size()) - 1;
        index = Math.max(0, Math.min(index, sortedSamples.size() - 1));
        return sortedSamples.get(index);
    }

    private void logLatencyStats(String label, List<Long> sortedSamples) {
        long p50 = percentile(sortedSamples, 50);
        long p95 = percentile(sortedSamples, 95);
        long p99 = percentile(sortedSamples, 99);
        log.info("[Performance] {} — p50={}ms  p95={}ms  p99={}ms  (n={})",
                label, p50, p95, p99, sortedSamples.size());
    }

    // -------------------------------------------------------------------------
    // Test 1: POST latency 
    // -------------------------------------------------------------------------

    @Test
    void postLatency_p95_shouldBeBelowThreshold() {
        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            timePost();
        }

        // Measure
        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = 0; i < MEASURE_REQUESTS; i++) {
            samples.add(timePost());
        }

        samples.sort(Long::compareTo);
        logLatencyStats("POST /api/v1/preferences", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < POST_P95_THRESHOLD_MS,
            String.format("POST p95 latency %dms exceeds threshold of %dms", p95, POST_P95_THRESHOLD_MS));
    }

    // -------------------------------------------------------------------------
    // Test 2: GET latency
    // -------------------------------------------------------------------------

    @Test
    void getLatency_p95_shouldBeBelowThreshold() {
        // Pre-create a preference to read
        String preferenceId = createPreference();

        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            timeGet(preferenceId);
        }

        // Measure
        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = 0; i < MEASURE_REQUESTS; i++) {
            samples.add(timeGet(preferenceId));
        }

        samples.sort(Long::compareTo);
        logLatencyStats("GET /api/v1/preferences/{id}", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < GET_P95_THRESHOLD_MS,
            String.format("GET p95 latency %dms exceeds threshold of %dms", p95, GET_P95_THRESHOLD_MS));
    }

    // -------------------------------------------------------------------------
    // Test 3: Throughput 
    // -------------------------------------------------------------------------

    @Test
    void getThroughput_shouldExceedMinimumRequestsPerSecond() {
        // Pre-create a preference to read
        String preferenceId = createPreference();

        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            timeGet(preferenceId);
        }

        // Measure throughput over sequential requests
        long startNs = System.nanoTime();
        for (int i = 0; i < THROUGHPUT_REQUESTS; i++) {
            given()
                .header("X-Tenant-Id", TENANT_ID)
            .when()
                .get(BASE_PATH + "/" + preferenceId)
            .then()
                .statusCode(200);
        }
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

        double rps = THROUGHPUT_REQUESTS / (elapsedMs / 1000.0);
        log.info("[Performance] GET throughput — {} req/s over {} requests in {}ms",
                String.format("%.2f", rps), THROUGHPUT_REQUESTS, elapsedMs);

        assertTrue(rps > THROUGHPUT_MIN_RPS,
            String.format("GET throughput %.2f req/s is below minimum of %.1f req/s", rps, THROUGHPUT_MIN_RPS));
    }
}
