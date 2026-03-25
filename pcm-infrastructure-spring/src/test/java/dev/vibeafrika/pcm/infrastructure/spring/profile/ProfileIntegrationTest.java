package dev.vibeafrika.pcm.infrastructure.spring.profile;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
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
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for the Profile context REST API.
 *
 * Uses Spring Boot Test with a random port, Testcontainers PostgreSQL,
 * and RestAssured for HTTP assertions. Tests the full stack from HTTP
 * through use cases to database persistence.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ProfileIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_test")
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

    private static final String TENANT_ID = "tenant-profile-integration";
    private static final String BASE_PATH = "/api/v1/profiles";

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.basePath = "";
    }

    // -------------------------------------------------------------------------
    // Helper: build a unique handle for each test to avoid conflicts
    // -------------------------------------------------------------------------

    private String uniqueHandle() {
        return "h" + UUID.randomUUID().toString().replace("-", "").substring(0, 15);
    }

    // -------------------------------------------------------------------------
    // Helper: build an update profile request body.
    // UpdateProfileRequest validates profileId in its compact constructor,
    // so we must include it in the body even though the controller overrides
    // it with the path variable.
    // -------------------------------------------------------------------------

    private Map<String, Object> updateBody(String profileId, Map<String, Object> attributes) {
        return Map.of(
            "profileId", profileId,
            "tenantId", TENANT_ID,
            "attributes", attributes
        );
    }

    // -------------------------------------------------------------------------
    // Helper: build a create profile request body.
    // CreateProfileRequest validates tenantId in its compact constructor,
    // so we must include it in the body even though the controller overrides
    // it with the X-Tenant-Id header value.
    // -------------------------------------------------------------------------

    private Map<String, Object> createBody(String handle, Map<String, Object> attributes) {
        return Map.of(
            "tenantId", TENANT_ID,
            "handle", handle,
            "attributes", attributes
        );
    }

    // -------------------------------------------------------------------------
    // 1. POST /api/v1/profiles → 201 Created with response body
    // -------------------------------------------------------------------------

    @Test
    void createProfile_returnsCreatedWithBody() {
        String handle = uniqueHandle();

        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of("email", "user@example.com")))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .contentType(ContentType.JSON)
            .body("id", notNullValue())
            .body("tenantId", equalTo(TENANT_ID))
            .body("handle", equalTo(handle))
            .body("attributes.email", equalTo("user@example.com"))
            .body("createdAt", notNullValue())
            .body("updatedAt", notNullValue())
            .body("version", notNullValue());
    }

    @Test
    void createProfile_withEmptyAttributes_returns201() {
        String handle = uniqueHandle();

        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .body("id", notNullValue())
            .body("handle", equalTo(handle));
    }

    // -------------------------------------------------------------------------
    // 2. GET /api/v1/profiles/{id} → 200 with correct data
    // -------------------------------------------------------------------------

    @Test
    void getProfile_returnsCorrectData() {
        String handle = uniqueHandle();

        // Create first
        String profileId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of("city", "Nairobi")))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        // Then get
        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("id", equalTo(profileId))
            .body("tenantId", equalTo(TENANT_ID))
            .body("handle", equalTo(handle))
            .body("attributes.city", equalTo("Nairobi"));
    }

    @Test
    void getProfile_notFound_returns404() {
        UUID nonExistentId = UUID.randomUUID();

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + nonExistentId)
        .then()
            .statusCode(404);
    }

    // -------------------------------------------------------------------------
    // 3. PUT /api/v1/profiles/{id} → 200 with updated data
    // -------------------------------------------------------------------------

    @Test
    void updateProfile_returnsUpdatedData() {
        String handle = uniqueHandle();

        // Create first
        String profileId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of("theme", "dark")))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        // Update
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(updateBody(profileId, Map.of("theme", "light", "language", "sw")))
        .when()
            .put(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("id", equalTo(profileId))
            .body("attributes.theme", equalTo("light"))
            .body("attributes.language", equalTo("sw"));
    }

    @Test
    void updateProfile_notFound_returns404() {
        UUID nonExistentId = UUID.randomUUID();

        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(updateBody(nonExistentId.toString(), Map.of("key", "value")))
        .when()
            .put(BASE_PATH + "/" + nonExistentId)
        .then()
            .statusCode(404);
    }

    // -------------------------------------------------------------------------
    // 4. DELETE /api/v1/profiles/{id} → 204 No Content (soft delete / erase)
    // -------------------------------------------------------------------------

    @Test
    void eraseProfile_returns204() {
        String handle = uniqueHandle();

        String profileId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(204);
    }

    @Test
    void eraseProfile_notFound_returns404() {
        UUID nonExistentId = UUID.randomUUID();

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + nonExistentId)
        .then()
            .statusCode(404);
    }

    // -------------------------------------------------------------------------
    // 5. Erased profile → 410 Gone on subsequent update
    // -------------------------------------------------------------------------

    @Test
    void updateErasedProfile_returns410() {
        String handle = uniqueHandle();

        // Create
        String profileId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        // Erase
        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(204);

        // Update erased profile → 410 GONE
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(updateBody(profileId, Map.of("key", "value")))
        .when()
            .put(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(410);
    }

    // -------------------------------------------------------------------------
    // 6. Duplicate handle → 400 Bad Request
    // -------------------------------------------------------------------------

    @Test
    void createProfile_duplicateHandle_returns400() {
        String handle = uniqueHandle();

        // Create first
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201);

        // Create duplicate
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(400);
    }

    // -------------------------------------------------------------------------
    // 7. Invalid handle format → 400 Bad Request
    // -------------------------------------------------------------------------

    @Test
    void createProfile_invalidHandle_returns400() {
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody("INVALID_UPPERCASE", Map.of()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(400);
    }

    @Test
    void createProfile_handleTooShort_returns400() {
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody("ab", Map.of()))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(400);
    }

    // -------------------------------------------------------------------------
    // 8. Database persistence verified via GET after POST
    // -------------------------------------------------------------------------

    @Test
    void createProfile_dataPersisted_verifiedByGet() {
        String handle = uniqueHandle();
        Map<String, Object> attributes = Map.of("country", "KE", "lang", "sw");

        String profileId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, attributes))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        // Verify data is actually persisted by fetching it
        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(200)
            .body("id", equalTo(profileId))
            .body("handle", equalTo(handle))
            .body("attributes.country", equalTo("KE"))
            .body("attributes.lang", equalTo("sw"));
    }

    @Test
    void updateProfile_dataPersisted_verifiedByGet() {
        String handle = uniqueHandle();

        String profileId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(createBody(handle, Map.of("v", "1")))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        // Update
        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(updateBody(profileId, Map.of("v", "2", "extra", "data")))
        .when()
            .put(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(200);

        // Verify update persisted
        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .get(BASE_PATH + "/" + profileId)
        .then()
            .statusCode(200)
            .body("attributes.v", equalTo("2"))
            .body("attributes.extra", equalTo("data"));
    }
}
