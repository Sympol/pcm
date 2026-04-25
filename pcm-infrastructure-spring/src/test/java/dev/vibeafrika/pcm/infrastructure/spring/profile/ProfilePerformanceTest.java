package dev.vibeafrika.pcm.infrastructure.spring.profile;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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
 * Performance baseline tests for the Profile context REST API.
 *
 * Measures p50/p95/p99 latency and throughput against the Spring Boot adapter.
 * Results are logged and asserted against thresholds within 5% of the pre-refactoring
 * baseline.
 *
 * Thresholds:
 * - POST p95 latency < 500ms
 * - GET  p95 latency < 200ms
 * - GET  throughput  > 10 req/s (sequential, single-threaded)
 */
@DisplayName("Profile Performance Baseline Tests")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ProfilePerformanceTest {

    private static final Logger log = LoggerFactory.getLogger(ProfilePerformanceTest.class);

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_profile_perf_test")
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

    private static final String TENANT_ID   = "tenant-profile-perf";
    private static final String BASE_PATH   = "/api/v1/profiles";

    private static final int  WARMUP_REQUESTS    = 10;
    private static final int  MEASURE_REQUESTS   = 50;
    private static final int  THROUGHPUT_REQUESTS = 100;

    private static final long   POST_P95_THRESHOLD_MS  = 500;
    private static final long   GET_P95_THRESHOLD_MS   = 200;
    private static final double THROUGHPUT_MIN_RPS      = 10.0;

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.basePath = "";
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Returns a handle guaranteed to be unique per call. */
    private String uniqueHandle() {
        return "h" + UUID.randomUUID().toString().replace("-", "").substring(0, 15);
    }

    /** Creates a profile and returns its ID. */
    private String createProfile() {
        String handle = uniqueHandle();
        return given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", handle, "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .statusCode(201)
                .extract().path("id");
    }

    /** Times a single POST create-profile request in ms. */
    private long timePost() {
        long start = System.nanoTime();
        given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", uniqueHandle(), "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .statusCode(201);
        return (System.nanoTime() - start) / 1_000_000;
    }

    /** Times a single GET by-id request in ms. */
    private long timeGet(String profileId) {
        long start = System.nanoTime();
        given()
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + profileId)
                .then()
                .statusCode(200);
        return (System.nanoTime() - start) / 1_000_000;
    }

    /** Returns the p-th percentile (0–100) from an already-sorted list. */
    private long percentile(List<Long> sorted, int p) {
        if (sorted.isEmpty()) return 0;
        int idx = (int) Math.ceil(p / 100.0 * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(idx, sorted.size() - 1)));
    }

    private void logStats(String label, List<Long> sorted) {
        log.info("[Perf] {} — p50={}ms  p95={}ms  p99={}ms  (n={})",
                label, percentile(sorted, 50), percentile(sorted, 95),
                percentile(sorted, 99), sorted.size());
    }

    // -------------------------------------------------------------------------
    // Test 1: POST latency 
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("POST /api/v1/profiles p95 latency is within threshold")
    void postLatency_p95_withinThreshold() {
        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) timePost();

        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = 0; i < MEASURE_REQUESTS; i++) samples.add(timePost());

        samples.sort(Long::compareTo);
        logStats("POST /api/v1/profiles", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < POST_P95_THRESHOLD_MS,
                String.format("POST p95=%dms exceeds threshold %dms", p95, POST_P95_THRESHOLD_MS));
    }

    // -------------------------------------------------------------------------
    // Test 2: GET latency 
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/v1/profiles/{id} p95 latency is within threshold")
    void getLatency_p95_withinThreshold() {
        String profileId = createProfile();

        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) timeGet(profileId);

        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = 0; i < MEASURE_REQUESTS; i++) samples.add(timeGet(profileId));

        samples.sort(Long::compareTo);
        logStats("GET /api/v1/profiles/{id}", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < GET_P95_THRESHOLD_MS,
                String.format("GET p95=%dms exceeds threshold %dms", p95, GET_P95_THRESHOLD_MS));
    }

    // -------------------------------------------------------------------------
    // Test 3: Throughput 
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/v1/profiles/{id} throughput exceeds minimum RPS")
    void getThroughput_exceedsMinimumRps() {
        String profileId = createProfile();

        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) timeGet(profileId);

        long startNs = System.nanoTime();
        for (int i = 0; i < THROUGHPUT_REQUESTS; i++) {
            given()
                    .header("X-Tenant-Id", TENANT_ID)
                    .when()
                    .get(BASE_PATH + "/" + profileId)
                    .then()
                    .statusCode(200);
        }
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

        double rps = THROUGHPUT_REQUESTS / (elapsedMs / 1000.0);
        log.info("[Perf] GET throughput — {:.2f} req/s over {} requests in {}ms",
                rps, THROUGHPUT_REQUESTS, elapsedMs);

        assertTrue(rps > THROUGHPUT_MIN_RPS,
                String.format("GET throughput %.2f req/s < minimum %.1f req/s", rps, THROUGHPUT_MIN_RPS));
    }

    // -------------------------------------------------------------------------
    // Test 4: PUT latency 
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("PUT /api/v1/profiles/{id} p95 latency is within POST threshold")
    void putLatency_p95_withinThreshold() {
        String profileId = createProfile();

        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            given()
                    .contentType(ContentType.JSON)
                    .header("X-Tenant-Id", TENANT_ID)
                    .body(Map.of("profileId", profileId, "tenantId", TENANT_ID,
                            "attributes", Map.of("warmup", String.valueOf(i))))
                    .when()
                    .put(BASE_PATH + "/" + profileId)
                    .then()
                    .statusCode(200);
        }

        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = 0; i < MEASURE_REQUESTS; i++) {
            long start = System.nanoTime();
            given()
                    .contentType(ContentType.JSON)
                    .header("X-Tenant-Id", TENANT_ID)
                    .body(Map.of("profileId", profileId, "tenantId", TENANT_ID,
                            "attributes", Map.of("iter", String.valueOf(i))))
                    .when()
                    .put(BASE_PATH + "/" + profileId)
                    .then()
                    .statusCode(200);
            samples.add((System.nanoTime() - start) / 1_000_000);
        }

        samples.sort(Long::compareTo);
        logStats("PUT /api/v1/profiles/{id}", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < POST_P95_THRESHOLD_MS,
                String.format("PUT p95=%dms exceeds threshold %dms", p95, POST_P95_THRESHOLD_MS));
    }
}
