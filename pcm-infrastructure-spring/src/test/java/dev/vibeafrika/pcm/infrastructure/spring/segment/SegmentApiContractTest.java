package dev.vibeafrika.pcm.infrastructure.spring.segment;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
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
import static org.assertj.core.api.Assertions.assertThat;

/**
 * API contract validation for the Segment context.
 *
 * Verifies HTTP methods, paths, request/response schemas, and status codes
 * match the expected contracts.
 *
 * Endpoints under test:
 *   POST   /api/v1/segments              → 201 Created
 *   GET    /api/v1/segments/{id}         → 200 OK
 *   PUT    /api/v1/segments/{id}         → 200 OK
 *   DELETE /api/v1/segments/{id}         → 204 No Content
 *   POST   /api/v1/segments/evaluate     → 200 OK (list)
 *
 * Response schema fields verified:
 *   id, tenantId, profileId, tags, scores, lastUpdated
 */
@DisplayName("Segment API Contract Validation")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class SegmentApiContractTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_segment_contract_test")
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

    private static final String TENANT_ID = "tenant-segment-contract";
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

    private String createSegment() {
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

    // -------------------------------------------------------------------------
    // Contract 1: POST /api/v1/segments
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("POST /api/v1/segments uses correct path and returns 201")
    void post_correctPathAndStatusCode() {
        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(UUID.randomUUID()))
        .when()
            .post(BASE_PATH)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("POST /api/v1/segments must return 201 Created")
            .isEqualTo(201);

        assertThat(response.contentType())
            .as("POST response must return JSON content-type")
            .contains("application/json");
    }

    @Test
    @DisplayName("POST /api/v1/segments response schema contains all required fields")
    void post_responseSchemaComplete() {
        UUID profileId = UUID.randomUUID();

        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "profileId", profileId.toString(),
                "tags", Set.of("music", "travel"),
                "scores", Map.of("relevance", 0.9)
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().response();

        // Verify complete response schema 
        assertThat(response.jsonPath().getString("id")).isNotNull();
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getString("profileId")).isEqualTo(profileId.toString());
        assertThat(response.jsonPath().getList("tags")).isNotNull();
        assertThat(response.jsonPath().getMap("scores")).isNotNull();
        assertThat(response.jsonPath().getString("lastUpdated")).isNotNull();
    }

    @Test
    @DisplayName("POST /api/v1/segments requires X-Tenant-Id header")
    void post_requiresTenantIdHeader() {
        Response response = given()
            .contentType(ContentType.JSON)
            .body(createBody(UUID.randomUUID()))
        .when()
            .post(BASE_PATH)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("Missing X-Tenant-Id header should return 4xx")
            .isBetween(400, 499);
    }

    // -------------------------------------------------------------------------
    // Contract 2: GET /api/v1/segments/{id}
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/v1/segments/{id} returns 200 with correct schema")
    void get_correctPathAndSchema() {
        UUID profileId = UUID.randomUUID();

        String segmentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "profileId", profileId.toString(),
                "tags", Set.of("fitness"),
                "scores", Map.of("relevance", 0.75)
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        Response response = given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + segmentId)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("GET /api/v1/segments/{id} must return 200 OK")
            .isEqualTo(200);

        assertThat(response.contentType()).contains("application/json");

        // Schema must match POST response schema 
        assertThat(response.jsonPath().getString("id")).isEqualTo(segmentId);
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getString("profileId")).isEqualTo(profileId.toString());
        assertThat(response.jsonPath().getList("tags")).isNotNull();
        assertThat(response.jsonPath().getMap("scores")).isNotNull();
        assertThat(response.jsonPath().getString("lastUpdated")).isNotNull();
    }

    @Test
    @DisplayName("GET /api/v1/segments/{id} non-existent returns 404 with RFC 7807 body")
    void get_nonExistent_returns404WithProblemDetail() {
        Response response = given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + UUID.randomUUID())
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("Non-existent segment GET must return 404")
            .isEqualTo(404);

        assertThat(response.contentType())
            .as("404 response must use application/problem+json")
            .contains("application/problem+json");

        assertThat(response.jsonPath().getString("type")).isNotBlank();
        assertThat(response.jsonPath().getString("title")).isNotBlank();
        assertThat(response.jsonPath().getInt("status")).isEqualTo(404);
        assertThat(response.jsonPath().getString("detail")).isNotBlank();
    }

    // -------------------------------------------------------------------------
    // Contract 3: PUT /api/v1/segments/{id}
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("PUT /api/v1/segments/{id} returns 200 with updated schema")
    void put_correctPathAndSchema() {
        String segmentId = createSegment();

        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "tags", Set.of("updated-tag"),
                "scores", Map.of("relevance", 0.95)
            ))
        .when()
            .put(BASE_PATH + "/" + segmentId)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("PUT /api/v1/segments/{id} must return 200 OK")
            .isEqualTo(200);

        assertThat(response.contentType()).contains("application/json");

        // Schema unchanged from GET response 
        assertThat(response.jsonPath().getString("id")).isEqualTo(segmentId);
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getList("tags")).isNotNull();
        assertThat(response.jsonPath().getMap("scores")).isNotNull();
        assertThat(response.jsonPath().getString("lastUpdated")).isNotNull();
    }

    @Test
    @DisplayName("PUT /api/v1/segments/{id} non-existent returns 404")
    void put_nonExistent_returns404() {
        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of("tags", Set.of("x"), "scores", Map.of("relevance", 0.5)))
        .when()
            .put(BASE_PATH + "/" + UUID.randomUUID())
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("PUT on non-existent segment must return 404")
            .isEqualTo(404);
    }

    // -------------------------------------------------------------------------
    // Contract 4: DELETE /api/v1/segments/{id}
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("DELETE /api/v1/segments/{id} returns 204 No Content")
    void delete_correctPathAndStatus() {
        String segmentId = createSegment();

        Response response = given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + segmentId)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("DELETE /api/v1/segments/{id} must return 204 No Content")
            .isEqualTo(204);

        assertThat(response.body().asString())
            .as("204 response must have empty body")
            .isEmpty();
    }

    @Test
    @DisplayName("DELETE /api/v1/segments/{id} non-existent returns 404")
    void delete_nonExistent_returns404() {
        Response response = given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + UUID.randomUUID())
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("DELETE non-existent segment must return 404")
            .isEqualTo(404);
    }

    // -------------------------------------------------------------------------
    // Contract 5: POST /api/v1/segments/evaluate
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("POST /api/v1/segments/evaluate returns 200 with list")
    void evaluate_correctPathAndSchema() {
        UUID profileId = UUID.randomUUID();

        // Create a segment for this profile first
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "profileId", profileId.toString(),
                "tags", Set.of("sports"),
                "scores", Map.of("relevance", 0.8)
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201);

        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of("profileId", profileId.toString()))
        .when()
            .post(BASE_PATH + "/evaluate")
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("POST /api/v1/segments/evaluate must return 200 OK")
            .isEqualTo(200);

        assertThat(response.contentType()).contains("application/json");
        assertThat(response.jsonPath().getList("$")).isNotNull();
    }
}
