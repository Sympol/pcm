package dev.vibeafrika.pcm.infrastructure.spring.consent;

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
 * Task 32.2: Performance baseline tests for the Consent context REST API.
 *
 * Validates ledger write performance and read throughput.
 *
 * Thresholds:
 * - POST (grant) p95 latency < 500ms
 * - GET  (verify) p95 latency < 200ms
 * - Throughput > 10 requests/second (sequential verify)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ConsentPerformanceTest {

    private static final Logger log = LoggerFactory.getLogger(ConsentPerformanceTest.class);

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_consent_perf_test")
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
    private static final String BASE_PATH = "/api/v1/consents";

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

    private Map<String, Object> grantBody() {
        return Map.of(
            "profileId", UUID.randomUUID().toString(),
            "tenantId", TENANT_ID,
            "purpose", "analytics",
            "scope", "page-views"
        );
    }

    private String grantConsent() {
        return given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody())
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");
    }

    private long timePost() {
        long start = System.nanoTime();
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody())
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201);
        return (System.nanoTime() - start) / 1_000_000;
    }

    private long timeVerify(String consentId) {
        long start = System.nanoTime();
        given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/verify")
        .then()
            .statusCode(200);
        return (System.nanoTime() - start) / 1_000_000;
    }

    private long percentile(List<Long> sorted, int p) {
        if (sorted.isEmpty()) return 0;
        int index = (int) Math.ceil(p / 100.0 * sorted.size()) - 1;
        index = Math.max(0, Math.min(index, sorted.size() - 1));
        return sorted.get(index);
    }

    private void logLatencyStats(String label, List<Long> sorted) {
        log.info("[Performance] {} — p50={}ms  p95={}ms  p99={}ms  (n={})",
            label,
            percentile(sorted, 50),
            percentile(sorted, 95),
            percentile(sorted, 99),
            sorted.size());
    }

    // -------------------------------------------------------------------------
    // Test 1: POST (grant) latency — ledger write performance
    // -------------------------------------------------------------------------

    @Test
    void postGrantLatency_p95_shouldBeBelowThreshold() {
        for (int i = 0; i < WARMUP_REQUESTS; i++) timePost();

        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = 0; i < MEASURE_REQUESTS; i++) samples.add(timePost());

        samples.sort(Long::compareTo);
        logLatencyStats("POST /api/v1/consents (grant)", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < POST_P95_THRESHOLD_MS,
            String.format("POST grant p95 latency %dms exceeds threshold of %dms (Requirement 17.1)", p95, POST_P95_THRESHOLD_MS));
    }

    // -------------------------------------------------------------------------
    // Test 2: GET (verify) latency
    // -------------------------------------------------------------------------

    @Test
    void getVerifyLatency_p95_shouldBeBelowThreshold() {
        String consentId = grantConsent();

        for (int i = 0; i < WARMUP_REQUESTS; i++) timeVerify(consentId);

        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = 0; i < MEASURE_REQUESTS; i++) samples.add(timeVerify(consentId));

        samples.sort(Long::compareTo);
        logLatencyStats("GET /api/v1/consents/verify", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < GET_P95_THRESHOLD_MS,
            String.format("GET verify p95 latency %dms exceeds threshold of %dms", p95, GET_P95_THRESHOLD_MS));
    }

    // -------------------------------------------------------------------------
    // Test 3: Throughput
    // -------------------------------------------------------------------------

    @Test
    void verifyThroughput_shouldExceedMinimumRequestsPerSecond() {
        String consentId = grantConsent();

        for (int i = 0; i < WARMUP_REQUESTS; i++) timeVerify(consentId);

        long startNs = System.nanoTime();
        for (int i = 0; i < THROUGHPUT_REQUESTS; i++) {
            given()
                .queryParam("consentId", consentId)
            .when()
                .get(BASE_PATH + "/verify")
            .then()
                .statusCode(200);
        }
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

        double rps = THROUGHPUT_REQUESTS / (elapsedMs / 1000.0);
        log.info("[Performance] GET verify throughput — {} req/s over {} requests in {}ms",
            String.format("%.2f", rps), THROUGHPUT_REQUESTS, elapsedMs);

        assertTrue(rps > THROUGHPUT_MIN_RPS,
            String.format("GET verify throughput %.2f req/s is below minimum of %.1f req/s", rps, THROUGHPUT_MIN_RPS));
    }

    // -------------------------------------------------------------------------
    // Test 4: Ledger write (revoke) latency — append-only pattern
    // -------------------------------------------------------------------------

    @Test
    void postRevokeLatency_p95_shouldBeBelowThreshold() {
        // Pre-create consents to revoke
        List<String> consentIds = new ArrayList<>();
        for (int i = 0; i < WARMUP_REQUESTS + MEASURE_REQUESTS; i++) {
            consentIds.add(grantConsent());
        }

        // Warm up
        for (int i = 0; i < WARMUP_REQUESTS; i++) {
            long start = System.nanoTime();
            given()
                .header("X-Tenant-Id", TENANT_ID)
            .when()
                .delete(BASE_PATH + "/" + consentIds.get(i))
            .then()
                .statusCode(200);
        }

        // Measure revoke (ledger write) latency
        List<Long> samples = new ArrayList<>(MEASURE_REQUESTS);
        for (int i = WARMUP_REQUESTS; i < WARMUP_REQUESTS + MEASURE_REQUESTS; i++) {
            long start = System.nanoTime();
            given()
                .header("X-Tenant-Id", TENANT_ID)
            .when()
                .delete(BASE_PATH + "/" + consentIds.get(i))
            .then()
                .statusCode(200);
            samples.add((System.nanoTime() - start) / 1_000_000);
        }

        samples.sort(Long::compareTo);
        logLatencyStats("DELETE /api/v1/consents/{id} (revoke/ledger write)", samples);

        long p95 = percentile(samples, 95);
        assertTrue(p95 < POST_P95_THRESHOLD_MS,
            String.format("Revoke (ledger write) p95 latency %dms exceeds threshold of %dms", p95, POST_P95_THRESHOLD_MS));
    }
}
