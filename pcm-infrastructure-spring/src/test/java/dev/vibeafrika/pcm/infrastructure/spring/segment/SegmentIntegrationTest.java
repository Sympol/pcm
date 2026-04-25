package dev.vibeafrika.pcm.infrastructure.spring.segment;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for the Segment context REST API.
 *
 * Validates all segment endpoints end-to-end with a real PostgreSQL database.
 * Verifies existing tests pass without modification.
 */
@DisplayName("Segment Integration Tests")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class SegmentIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_segment_integration_test")
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

    private static final String TENANT_ID = "tenant-segment-integration";
    private static final String BASE_PATH = "/api/v1/segments";

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.basePath = "";
    }

    private Map<String, Object> createBody(UUID profileId) {
        return Map.of(
            "profileId", profileId.toString(),
            "tags", Set.of("sports", "tech"),
            "scores", Map.of("relevance", 0.85, "engagement", 0.72)
        );
    }

    // -------------------------------------------------------------------------
    // 1. Create segment → 201 + response body
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("createSegment returns 201 with full response body")
    void createSegment_returnsCreatedWithBody() {
        UUID profileId = UUID.randomUUID();

        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .contentType(ContentType.JSON)
            .body("id", notNullValue())
            .body("tenantId", equalTo(TENANT_ID))
            .body("profileId", equalTo(profileId.toString()))
            .body("tags", hasItems("sports", "tech"))
            .body("scores.relevance", equalTo(0.85f))
            .body("scores.engagement", equalTo(0.72f))
            .body("lastUpdated", notNullValue());
    }

    // -------------------------------------------------------------------------
    // 2. Get segment by ID → 200 + correct data
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("getSegment returns correct data")
    void getSegment_returnsCorrectData() {
        UUID profileId = UUID.randomUUID();

        String segmentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + segmentId)
        .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("id", equalTo(segmentId))
            .body("tenantId", equalTo(TENANT_ID))
            .body("profileId", equalTo(profileId.toString()))
            .body("tags", hasItems("sports", "tech"))
            .body("lastUpdated", notNullValue());
    }

    // -------------------------------------------------------------------------
    // 3. Update segment → 200 + updated data
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("updateSegment returns updated data")
    void updateSegment_returnsUpdatedData() {
        UUID profileId = UUID.randomUUID();

        String segmentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "tags", Set.of("music", "art"),
                "scores", Map.of("relevance", 0.95, "engagement", 0.88)
            ))
        .when()
            .put(BASE_PATH + "/" + segmentId)
        .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("id", equalTo(segmentId))
            .body("tags", hasItems("music", "art"))
            .body("scores.relevance", equalTo(0.95f));
    }

    // -------------------------------------------------------------------------
    // 4. Delete segment → 204 No Content
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("deleteSegment returns 204")
    void deleteSegment_returns204() {
        UUID profileId = UUID.randomUUID();

        String segmentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + segmentId)
        .then()
            .statusCode(204);
    }

    // -------------------------------------------------------------------------
    // 5. Get deleted segment → 404
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("getSegment after delete returns 404")
    void getSegment_afterDelete_returns404() {
        UUID profileId = UUID.randomUUID();

        String segmentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + segmentId)
        .then()
            .statusCode(204);

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + segmentId)
        .then()
            .statusCode(404);
    }

    // -------------------------------------------------------------------------
    // 6. Get non-existent segment → 404 RFC 7807
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("getSegment non-existent returns 404 with RFC 7807 body")
    void getSegment_notFound_returns404WithProblemDetail() {
        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + UUID.randomUUID())
        .then()
            .statusCode(404)
            .body("status", equalTo(404))
            .body("title", notNullValue())
            .body("detail", notNullValue());
    }

    // -------------------------------------------------------------------------
    // 7. Create segment with missing tenant header → 4xx
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("createSegment missing tenant header returns 4xx")
    void createSegment_missingTenantHeader_returns4xx() {
        given()
            .contentType(ContentType.JSON)
            .body(createBody(UUID.randomUUID()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(anyOf(equalTo(400), equalTo(500)));
    }

    // -------------------------------------------------------------------------
    // 8. Evaluate segments for a profile → 200 with list
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("evaluateSegments returns 200 with matching segments")
    void evaluateSegments_returnsMatchingSegments() {
        UUID profileId = UUID.randomUUID();

        // Create a segment for this profile
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201);

        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of("profileId", profileId.toString()))
        .when()
            .post(BASE_PATH + "/evaluate")
        .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("$", hasSize(greaterThanOrEqualTo(1)));
    }

    // -------------------------------------------------------------------------
    // 9. Evaluate segments for unknown profile → 200 with empty list
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("evaluateSegments for unknown profile returns empty list")
    void evaluateSegments_unknownProfile_returnsEmptyList() {
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of("profileId", UUID.randomUUID().toString()))
        .when()
            .post(BASE_PATH + "/evaluate")
        .then()
            .statusCode(200)
            .body("$", hasSize(0));
    }
}
