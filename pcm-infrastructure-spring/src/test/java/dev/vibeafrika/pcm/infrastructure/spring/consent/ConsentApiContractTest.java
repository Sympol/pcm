package dev.vibeafrika.pcm.infrastructure.spring.consent;

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
 * API contract validation for the Consent context.
 *
 * Verifies HTTP methods, paths, request/response schemas, and status codes
 * match the expected contracts.
 *
 * Endpoints under test:
 *   POST   /api/v1/consents              → 201 Created
 *   DELETE /api/v1/consents/{id}         → 200 OK (with revoked consent body)
 *   GET    /api/v1/consents/verify       → 200 OK (boolean)
 *   GET    /api/v1/consents/history      → 200 OK (history)
 */
@DisplayName("Consent API Contract Validation")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ConsentApiContractTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_consent_contract_test")
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
    private static final String BASE_PATH = "/api/v1/consents";

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.basePath = "";
    }

    private String grantConsent(UUID profileId, String purpose, String scope) {
        return given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "profileId", profileId.toString(),
                "tenantId", TENANT_ID,
                "purpose", purpose,
                "scope", scope
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");
    }

    // -------------------------------------------------------------------------
    // Contract 1: POST /api/v1/consents
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("POST /api/v1/consents uses correct path and returns 201")
    void post_correctPathAndStatusCode() {
        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "profileId", UUID.randomUUID().toString(),
                "tenantId", TENANT_ID,
                "purpose", "analytics",
                "scope", "page-views"
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("POST /api/v1/consents must return 201 Created")
            .isEqualTo(201);

        assertThat(response.contentType())
            .as("POST response must return JSON content-type")
            .contains("application/json");
    }

    @Test
    @DisplayName("POST /api/v1/consents response schema contains all required fields")
    void post_responseSchemaComplete() {
        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "profileId", UUID.randomUUID().toString(),
                "tenantId", TENANT_ID,
                "purpose", "marketing-emails",
                "scope", "email-notifications"
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().response();

        assertThat(response.jsonPath().getString("id")).isNotNull();
        assertThat(response.jsonPath().getString("profileId")).isNotNull();
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getString("purpose")).isEqualTo("marketing-emails");
        assertThat(response.jsonPath().getString("scope")).isEqualTo("email-notifications");
        assertThat(response.jsonPath().getString("status")).isEqualTo("GRANTED");
        assertThat(response.jsonPath().getString("createdAt")).isNotNull();
        assertThat(response.jsonPath().getString("updatedAt")).isNotNull();
        assertThat((Object) response.jsonPath().get("version")).isNotNull();
    }

    @Test
    @DisplayName("POST /api/v1/consents requires X-Tenant-Id header")
    void post_requiresTenantIdHeader() {
        Response response = given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "profileId", UUID.randomUUID().toString(),
                "tenantId", TENANT_ID,
                "purpose", "analytics",
                "scope", "page-views"
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("Missing X-Tenant-Id header should return 4xx")
            .isBetween(400, 499);
    }

    @Test
    @DisplayName("POST /api/v1/consents with blank purpose returns 4xx")
    void post_blankPurpose_returns4xx() {
        Response response = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(Map.of(
                "profileId", UUID.randomUUID().toString(),
                "tenantId", TENANT_ID,
                "purpose", "",
                "scope", "page-views"
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("Blank purpose should return 4xx")
            .isBetween(400, 499);
    }

    // -------------------------------------------------------------------------
    // Contract 2: DELETE /api/v1/consents/{id}
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("DELETE /api/v1/consents/{id} returns 200 with revoked consent body")
    void delete_correctPathAndSchema() {
        String consentId = grantConsent(UUID.randomUUID(), "analytics", "page-views");

        Response response = given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + consentId)
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("DELETE /api/v1/consents/{id} must return 200 OK")
            .isEqualTo(200);

        assertThat(response.contentType()).contains("application/json");

        // Schema must match ConsentResponse
        assertThat(response.jsonPath().getString("id")).isEqualTo(consentId);
        assertThat(response.jsonPath().getString("status")).isEqualTo("REVOKED");
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(TENANT_ID);
        assertThat(response.jsonPath().getString("updatedAt")).isNotNull();
    }

    @Test
    @DisplayName("DELETE /api/v1/consents/{id} non-existent returns 404 with RFC 7807 body")
    void delete_nonExistent_returns404WithProblemDetail() {
        Response response = given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + UUID.randomUUID())
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("Non-existent consent DELETE must return 404")
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
    // Contract 3: GET /api/v1/consents/verify
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/v1/consents/verify returns 200 with boolean true for active consent")
    void verify_activeConsent_returns200True() {
        String consentId = grantConsent(UUID.randomUUID(), "analytics", "page-views");

        Response response = given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/verify")
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("GET /api/v1/consents/verify must return 200 OK")
            .isEqualTo(200);

        assertThat(response.body().asString())
            .as("Active consent verify must return true")
            .isEqualTo("true");
    }

    @Test
    @DisplayName("GET /api/v1/consents/verify returns false for revoked consent")
    void verify_revokedConsent_returnsFalse() {
        String consentId = grantConsent(UUID.randomUUID(), "analytics", "page-views");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + consentId)
        .then()
            .statusCode(200);

        Response response = given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/verify")
        .then()
            .extract().response();

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body().asString()).isEqualTo("false");
    }

    // -------------------------------------------------------------------------
    // Contract 4: GET /api/v1/consents/history
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/v1/consents/history returns 200 with events array")
    void history_returnsEventsArray() {
        String consentId = grantConsent(UUID.randomUUID(), "analytics", "page-views");

        Response response = given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/history")
        .then()
            .extract().response();

        assertThat(response.statusCode())
            .as("GET /api/v1/consents/history must return 200 OK")
            .isEqualTo(200);

        assertThat(response.contentType()).contains("application/json");

        // Schema: { events: [ { status, timestamp } ] }
        assertThat(response.jsonPath().getList("events")).isNotNull();
        assertThat(response.jsonPath().getList("events").size()).isGreaterThanOrEqualTo(1);
        assertThat(response.jsonPath().getString("events[0].status")).isNotBlank();
        assertThat(response.jsonPath().getString("events[0].timestamp")).isNotBlank();
    }

}
