package dev.vibeafrika.pcm.infrastructure.spring.consent;

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
 * Integration tests for the Consent context REST API.
 *
 * Validates all consent endpoints end-to-end with a real PostgreSQL database.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ConsentIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_consent_test")
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

    private static final String TENANT_ID = "tenant-consent-integration";
    private static final String BASE_PATH = "/api/v1/consents";

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.basePath = "";
    }

    private Map<String, Object> grantBody(UUID profileId) {
        return Map.of(
            "profileId", profileId.toString(),
            "tenantId", TENANT_ID,
            "purpose", "marketing-emails",
            "scope", "email-notifications"
        );
    }

    // -------------------------------------------------------------------------
    // 1. Grant consent → 201 + response body
    // -------------------------------------------------------------------------

    @Test
    void grantConsent_returnsCreatedWithBody() {
        UUID profileId = UUID.randomUUID();

        given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .contentType(ContentType.JSON)
            .body("id", notNullValue())
            .body("profileId", equalTo(profileId.toString()))
            .body("tenantId", equalTo(TENANT_ID))
            .body("purpose", equalTo("marketing-emails"))
            .body("scope", equalTo("email-notifications"))
            .body("status", equalTo("GRANTED"))
            .body("createdAt", notNullValue())
            .body("updatedAt", notNullValue())
            .body("version", notNullValue());
    }

    // -------------------------------------------------------------------------
    // 2. Revoke consent → 200 with REVOKED status
    // -------------------------------------------------------------------------

    @Test
    void revokeConsent_returnsOkWithRevokedStatus() {
        UUID profileId = UUID.randomUUID();

        String consentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + consentId)
        .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("id", equalTo(consentId))
            .body("status", equalTo("REVOKED"));
    }

    // -------------------------------------------------------------------------
    // 3. Verify active consent → true
    // -------------------------------------------------------------------------

    @Test
    void verifyConsent_activeConsent_returnsTrue() {
        UUID profileId = UUID.randomUUID();

        String consentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/verify")
        .then()
            .statusCode(200)
            .body(equalTo("true"));
    }

    // -------------------------------------------------------------------------
    // 4. Verify revoked consent → false
    // -------------------------------------------------------------------------

    @Test
    void verifyConsent_revokedConsent_returnsFalse() {
        UUID profileId = UUID.randomUUID();

        String consentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + consentId)
        .then()
            .statusCode(200);

        given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/verify")
        .then()
            .statusCode(200)
            .body(equalTo("false"));
    }

    // -------------------------------------------------------------------------
    // 5. Get consent history → ledger events
    // -------------------------------------------------------------------------

    @Test
    void getConsentHistory_afterGrantAndRevoke_returnsTwoEvents() {
        UUID profileId = UUID.randomUUID();

        String consentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + consentId)
        .then()
            .statusCode(200);

        given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/history")
        .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("events", hasSize(greaterThanOrEqualTo(2)))
            .body("events[0].status", equalTo("GRANTED"))
            .body("events[0].timestamp", notNullValue());
    }

    // -------------------------------------------------------------------------
    // 6. Revoke already-revoked consent → 4xx (domain exception)
    // -------------------------------------------------------------------------

    @Test
    void revokeConsent_alreadyRevoked_returns4xx() {
        UUID profileId = UUID.randomUUID();

        String consentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + consentId)
        .then()
            .statusCode(200);

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + consentId)
        .then()
            .statusCode(anyOf(equalTo(409), equalTo(400), equalTo(422)));
    }

    // -------------------------------------------------------------------------
    // 7. Grant consent with missing tenant header → 4xx
    // -------------------------------------------------------------------------

    @Test
    void grantConsent_missingTenantHeader_returns4xx() {
        UUID profileId = UUID.randomUUID();

        given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "profileId", profileId.toString(),
                "tenantId", TENANT_ID,
                "purpose", "analytics",
                "scope", "page-views"
            ))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(anyOf(equalTo(400), equalTo(500)));
    }

    // -------------------------------------------------------------------------
    // 8. Revoke non-existent consent → 404
    // -------------------------------------------------------------------------

    @Test
    void revokeConsent_notFound_returns404() {
        UUID nonExistentId = UUID.randomUUID();

        given()
            .header("X-Tenant-Id", TENANT_ID)
        .when()
            .delete(BASE_PATH + "/" + nonExistentId)
        .then()
            .statusCode(404);
    }

    // -------------------------------------------------------------------------
    // 9. Ledger immutability: grant creates initial event
    // -------------------------------------------------------------------------

    @Test
    void grantConsent_historyContainsInitialGrantEvent() {
        UUID profileId = UUID.randomUUID();

        String consentId = given()
            .contentType(ContentType.JSON)
            .header("X-Tenant-Id", TENANT_ID)
            .body(grantBody(profileId))
        .when()
            .post(BASE_PATH)
        .then()
            .statusCode(201)
            .extract().path("id");

        given()
            .queryParam("consentId", consentId)
        .when()
            .get(BASE_PATH + "/history")
        .then()
            .statusCode(200)
            .body("events", hasSize(greaterThanOrEqualTo(1)))
            .body("events[0].status", equalTo("GRANTED"));
    }
}
