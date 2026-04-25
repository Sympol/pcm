package dev.vibeafrika.pcm.infrastructure.spring.profile;

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
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 24.2: API contract validation for the Profile context.
 *
 * Verifies that HTTP methods, paths, request/response schemas, and status codes
 * match the expected contracts.
 *
 * Endpoints under test:
 *   POST   /api/v1/profiles           → 201 Created
 *   GET    /api/v1/profiles/{id}      → 200 OK
 *   PUT    /api/v1/profiles/{id}      → 200 OK
 *   DELETE /api/v1/profiles/{id}      → 204 No Content
 *
 * Response schema fields verified:
 *   id, tenantId, handle, attributes, createdAt, updatedAt, version
 */
@DisplayName("Profile API Contract Validation")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ProfileApiContractTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_contract_test")
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

    private static final String TENANT_ID = "tenant-contract-test";
    private static final String BASE_PATH = "/api/v1/profiles";

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.basePath = "";
    }

    private String uniqueHandle() {
        return "h" + UUID.randomUUID().toString().replace("-", "").substring(0, 15);
    }

    // -------------------------------------------------------------------------
    // Contract 1: POST /api/v1/profiles
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("POST /api/v1/profiles uses correct path and returns 201")
    void post_correctPathAndStatusCode() {
        Response response = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", uniqueHandle(), "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("POST /api/v1/profiles must return 201 Created")
                .isEqualTo(201);

        assertThat(response.contentType())
                .as("POST response must return JSON content-type")
                .contains("application/json");
    }

    @Test
    @DisplayName("POST /api/v1/profiles response schema contains all required fields")
    void post_responseSchemaComplete() {
        Response response = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", uniqueHandle(),
                        "attributes", Map.of("email", "user@example.com")))
                .when()
                .post(BASE_PATH)
                .then()
                .statusCode(201)
                .extract().response();

        // Verify complete response schema
        assertThat(response.jsonPath().getString("id")).isNotNull();
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getString("handle")).isNotNull();
        assertThat(response.jsonPath().getMap("attributes")).isNotNull();
        assertThat(response.jsonPath().getString("createdAt")).isNotNull();
        assertThat(response.jsonPath().getString("updatedAt")).isNotNull();
        assertThat((Object) response.jsonPath().get("version")).isNotNull();
    }

    @Test
    @DisplayName("POST /api/v1/profiles requires X-Tenant-Id header")
    void post_requiresTenantIdHeader() {
        // Contract: X-Tenant-Id header is required
        Response response = given()
                .contentType(ContentType.JSON)
                .body(Map.of("tenantId", TENANT_ID, "handle", uniqueHandle(), "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Missing X-Tenant-Id header should return 4xx")
                .isBetween(400, 499);
    }

    @Test
    @DisplayName("POST /api/v1/profiles invalid handle returns 400")
    void post_invalidHandle_returns400() {
        Response response = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", "INVALID_UPPERCASE", "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Invalid handle should return 400 BAD_REQUEST")
                .isEqualTo(400);
    }

    // -------------------------------------------------------------------------
    // Contract 2: GET /api/v1/profiles/{id}
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/v1/profiles/{id} returns 200 with correct schema")
    void get_correctPathAndSchema() {
        String handle = uniqueHandle();

        String profileId = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", handle, "attributes", Map.of("city", "Lagos")))
                .when()
                .post(BASE_PATH)
                .then()
                .statusCode(201)
                .extract().path("id");

        Response response = given()
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("GET /api/v1/profiles/{id} must return 200 OK")
                .isEqualTo(200);

        assertThat(response.contentType()).contains("application/json");

        // Verify schema fields match the POST response schema
        assertThat(response.jsonPath().getString("id")).isEqualTo(profileId);
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getString("handle")).isEqualTo(handle);
        assertThat(response.jsonPath().getMap("attributes")).isNotNull();
        assertThat(response.jsonPath().getString("createdAt")).isNotNull();
        assertThat(response.jsonPath().getString("updatedAt")).isNotNull();
        assertThat((Object) response.jsonPath().get("version")).isNotNull();
    }

    @Test
    @DisplayName("GET /api/v1/profiles/{id} non-existent returns 404 with RFC 7807 body")
    void get_nonExistent_returns404WithProblemDetail() {
        Response response = given()
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + UUID.randomUUID())
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Non-existent profile GET must return 404")
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
    // Contract 3: PUT /api/v1/profiles/{id}
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("PUT /api/v1/profiles/{id} returns 200 with updated schema")
    void put_correctPathAndSchema() {
        String handle = uniqueHandle();

        String profileId = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", handle, "attributes", Map.of("v", "1")))
                .when()
                .post(BASE_PATH)
                .then()
                .statusCode(201)
                .extract().path("id");

        Response response = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("profileId", profileId, "tenantId", TENANT_ID, "attributes", Map.of("v", "2")))
                .when()
                .put(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("PUT /api/v1/profiles/{id} must return 200 OK")
                .isEqualTo(200);

        assertThat(response.contentType()).contains("application/json");

        // Schema unchanged from GET response
        assertThat(response.jsonPath().getString("id")).isEqualTo(profileId);
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getMap("attributes")).isNotNull();
        assertThat(response.jsonPath().getString("updatedAt")).isNotNull();
    }

    @Test
    @DisplayName("PUT /api/v1/profiles/{id} on deleted profile returns 410 Gone")
    void put_deletedProfile_returns410() {
        String handle = uniqueHandle();

        String profileId = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", handle, "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .statusCode(201)
                .extract().path("id");

        given().header("X-Tenant-Id", TENANT_ID)
                .when().delete(BASE_PATH + "/" + profileId)
                .then().statusCode(204);

        Response response = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("profileId", profileId, "tenantId", TENANT_ID, "attributes", Map.of("x", "y")))
                .when()
                .put(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("PUT on erased profile must return 410 Gone")
                .isEqualTo(410);
    }

    // -------------------------------------------------------------------------
    // Contract 4: DELETE /api/v1/profiles/{id}
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("DELETE /api/v1/profiles/{id} returns 204 No Content")
    void delete_correctPathAndStatus() {
        String profileId = given()
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("tenantId", TENANT_ID, "handle", uniqueHandle(), "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .statusCode(201)
                .extract().path("id");

        Response response = given()
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .delete(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("DELETE /api/v1/profiles/{id} must return 204 No Content")
                .isEqualTo(204);

        assertThat(response.body().asString())
                .as("204 response must have empty body")
                .isEmpty();
    }

    @Test
    @DisplayName("DELETE /api/v1/profiles/{id} non-existent returns 404")
    void delete_nonExistent_returns404() {
        Response response = given()
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .delete(BASE_PATH + "/" + UUID.randomUUID())
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("DELETE non-existent profile must return 404")
                .isEqualTo(404);
    }
}
