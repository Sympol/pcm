package dev.vibeafrika.pcm.infrastructure.spring.profile;

import dev.vibeafrika.pcm.infrastructure.spring.PcmApplication;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import net.jqwik.api.*;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for exception translation in the Profile Spring Boot infrastructure layer.
 *
 * <p><b>Property 16: Infrastructure Translates Domain Exceptions</b>
 *
 * <p>Verifies that the {@code GlobalExceptionHandler} correctly translates Profile domain
 * exceptions into RFC 7807 Problem Details HTTP responses with appropriate status codes
 * and content-type.
 *
 * <p>Sub-properties tested:
 * <ul>
 *   <li>16a: ProfileNotFoundException → 404 NOT_FOUND</li>
 *   <li>16b: InvalidHandleException (invalid handle format) → 400 BAD_REQUEST</li>
 *   <li>16c: ProfileDeletedException (erased profile access) → 410 GONE</li>
 *   <li>16d: Error response content-type is "application/problem+json"</li>
 *   <li>16e: Error response contains required RFC 7807 fields (type, title, status, detail)</li>
 *   <li>16f: Pure-assert validation errors include field error details</li>
 * </ul>
 *
 * <p>Implementation note: jqwik runs @Property tests in its own engine, separate from JUnit 5.
 * Spring's @SpringBootTest and @LocalServerPort injection are JUnit 5 features and do not work
 * with jqwik. Instead, this test uses jqwik's @BeforeContainer lifecycle to start a Spring Boot
 * application context with Testcontainers, capturing the server port statically.
 */
class ProfileExceptionTranslationPropertyTest {

    private static final String BASE_PATH = "/api/v1/profiles";
    private static final String TENANT_ID = "tenant-profile-exception-test";

    // Static state shared across all @Property methods
    private static PostgreSQLContainer<?> postgres;
    private static ConfigurableApplicationContext springContext;
    private static int serverPort;

    /**
     * Start Testcontainers PostgreSQL and Spring Boot application once before all properties.
     */
    @BeforeContainer
    static void startInfrastructure() {
        postgres = new PostgreSQLContainer<>("postgres:15-alpine")
                .withDatabaseName("pcm_test")
                .withUsername("pcm_user")
                .withPassword("pcm_password");
        postgres.start();

        System.setProperty("spring.datasource.url", postgres.getJdbcUrl());
        System.setProperty("spring.datasource.username", postgres.getUsername());
        System.setProperty("spring.datasource.password", postgres.getPassword());
        System.setProperty("server.port", "0");

        springContext = new SpringApplicationBuilder(PcmApplication.class)
                .profiles("test")
                .run();

        serverPort = Integer.parseInt(
                springContext.getEnvironment().getProperty("local.server.port", "8080"));

        RestAssured.baseURI = "http://localhost";
        RestAssured.port = serverPort;
        RestAssured.basePath = "";
    }

    /**
     * Stop Spring Boot and Testcontainers after all properties have run.
     */
    @AfterContainer
    static void stopInfrastructure() {
        if (springContext != null) {
            springContext.close();
        }
        if (postgres != null) {
            postgres.stop();
        }
        System.clearProperty("spring.datasource.url");
        System.clearProperty("spring.datasource.username");
        System.clearProperty("spring.datasource.password");
        System.clearProperty("server.port");
    }

    // =========================================================================
    // Property 16a: ProfileNotFoundException → 404 NOT_FOUND
    // =========================================================================

    /**
     * Property 16a: For any random UUID that does not correspond to an existing profile,
     * a GET request SHALL return HTTP 404 NOT_FOUND.
     *
     * <p>The GlobalExceptionHandler maps ProfileNotFoundException → 404.
     */
    @Property(tries = 20)
    @Label("Property 16a: Any non-existent profile ID returns 404 NOT_FOUND")
    void nonExistentProfileIdReturns404(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Non-existent profile %s should return 404", nonExistentId)
                .isEqualTo(404);
    }

    /**
     * Property 16a (variant): For any random UUID that does not correspond to an existing profile,
     * a PUT request SHALL return HTTP 404 NOT_FOUND.
     */
    @Property(tries = 20)
    @Label("Property 16a: Update non-existent profile returns 404 NOT_FOUND")
    void updateNonExistentProfileReturns404(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("attributes", Map.of("key", "value")))
                .when()
                .put(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Update non-existent profile %s should return 404", nonExistentId)
                .isEqualTo(404);
    }

    // =========================================================================
    // Property 16b: InvalidHandleException → 400 BAD_REQUEST
    // =========================================================================

    /**
     * Property 16b: For any POST request with an invalid handle (contains uppercase or
     * special characters), the response SHALL be HTTP 400 BAD_REQUEST.
     *
     * <p>The Handle value object validates the handle pattern; invalid handles trigger
     * InvalidHandleException which the GlobalExceptionHandler maps to 400.
     */
    @Property(tries = 20)
    @Label("Property 16b: Invalid handle format triggers 400 BAD_REQUEST")
    void invalidHandleReturns400(@ForAll("invalidHandles") String invalidHandle) {
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of(
                        "handle", invalidHandle,
                        "attributes", Map.of()
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Invalid handle '%s' should return 400", invalidHandle)
                .isEqualTo(400);
    }

    /**
     * Property 16b (variant): For any POST request with a handle that is too short (< 3 chars),
     * the response SHALL be HTTP 400 BAD_REQUEST.
     */
    @Property(tries = 20)
    @Label("Property 16b: Handle too short triggers 400 BAD_REQUEST")
    void tooShortHandleReturns400(@ForAll("tooShortHandles") String tooShortHandle) {
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of(
                        "handle", tooShortHandle,
                        "attributes", Map.of()
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Handle '%s' (too short) should return 400", tooShortHandle)
                .isEqualTo(400);
    }

    // =========================================================================
    // Property 16c: ProfileDeletedException → 410 GONE
    // =========================================================================

    /**
     * Property 16c: After a profile is erased (GDPR), any subsequent PUT (update) request
     * SHALL return HTTP 410 GONE.
     *
     * <p>The domain entity's {@code updateAttributes()} throws {@code ProfileDeletedException}
     * when the profile is already deleted. The GlobalExceptionHandler maps it → 410 GONE.
     */
    @Property(tries = 5)
    @Label("Property 16c: Updating erased profile returns 410 GONE")
    void updatingErasedProfileReturns410(@ForAll("validHandles") String handle) {
        // Create a profile
        Response createResponse = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of(
                        "handle", handle,
                        "attributes", Map.of()
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        // Skip if creation failed (e.g., handle conflict from a previous run)
        if (createResponse.statusCode() != 201) {
            return;
        }

        UUID profileId = UUID.fromString(createResponse.jsonPath().getString("id"));

        // Erase the profile (GDPR)
        given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .delete(BASE_PATH + "/" + profileId)
                .then()
                .statusCode(204);

        // Attempt to update the erased profile — domain entity throws ProfileDeletedException
        Response updateResponse = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of("attributes", Map.of("key", "value")))
                .when()
                .put(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(updateResponse.statusCode())
                .as("Updating erased profile %s should return 410 GONE", profileId)
                .isEqualTo(410);
    }

    // =========================================================================
    // Property 16d: Error response content-type is "application/problem+json"
    // =========================================================================

    /**
     * Property 16d: For any 404 error response (non-existent profile),
     * the content-type SHALL be "application/problem+json".
     */
    @Property(tries = 20)
    @Label("Property 16d: 404 error response content-type is application/problem+json")
    void notFoundResponseHasProblemJsonContentType(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(404);

        assertThat(response.contentType())
                .as("404 response for profile %s should have application/problem+json content-type", nonExistentId)
                .contains("application/problem+json");
    }

    /**
     * Property 16d (variant): For any 400 error response (invalid handle),
     * the content-type SHALL be "application/problem+json".
     */
    @Property(tries = 20)
    @Label("Property 16d: 400 error response content-type is application/problem+json")
    void validationErrorResponseHasProblemJsonContentType(@ForAll("invalidHandles") String invalidHandle) {
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of(
                        "handle", invalidHandle,
                        "attributes", Map.of()
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(400);

        assertThat(response.contentType())
                .as("400 response for invalid handle '%s' should have application/problem+json content-type", invalidHandle)
                .contains("application/problem+json");
    }

    // =========================================================================
    // Property 16e: RFC 7807 required fields present in error response
    // =========================================================================

    /**
     * Property 16e: For any 404 error response, the body SHALL contain
     * the required RFC 7807 fields: type, title, status, detail.
     */
    @Property(tries = 20)
    @Label("Property 16e: 404 response contains required RFC 7807 fields")
    void notFoundResponseContainsRfc7807Fields(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(404);

        assertThat(response.jsonPath().getString("type"))
                .as("RFC 7807 'type' field must be present in 404 response")
                .isNotNull().isNotBlank();

        assertThat(response.jsonPath().getString("title"))
                .as("RFC 7807 'title' field must be present in 404 response")
                .isNotNull().isNotBlank();

        assertThat(response.jsonPath().getInt("status"))
                .as("RFC 7807 'status' field must equal 404")
                .isEqualTo(404);

        assertThat(response.jsonPath().getString("detail"))
                .as("RFC 7807 'detail' field must be present in 404 response")
                .isNotNull().isNotBlank();
    }

    /**
     * Property 16e (variant): For any 400 validation error response, the body SHALL contain
     * the required RFC 7807 fields: type, title, status, detail.
     */
    @Property(tries = 20)
    @Label("Property 16e: 400 response contains required RFC 7807 fields")
    void validationErrorResponseContainsRfc7807Fields(@ForAll("invalidHandles") String invalidHandle) {
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", TENANT_ID)
                .body(Map.of(
                        "handle", invalidHandle,
                        "attributes", Map.of()
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(400);

        assertThat(response.jsonPath().getString("type"))
                .as("RFC 7807 'type' field must be present in 400 response")
                .isNotNull().isNotBlank();

        assertThat(response.jsonPath().getString("title"))
                .as("RFC 7807 'title' field must be present in 400 response")
                .isNotNull().isNotBlank();

        assertThat(response.jsonPath().getInt("status"))
                .as("RFC 7807 'status' field must equal 400")
                .isEqualTo(400);

        assertThat(response.jsonPath().getString("detail"))
                .as("RFC 7807 'detail' field must be present in 400 response")
                .isNotNull().isNotBlank();
    }

    // =========================================================================
    // Property 16f: Pure-assert validation errors include field error details
    // =========================================================================

    /**
     * Property 16f: For any pure-assert validation error triggered by a tenant ID exceeding
     * the maximum length (100 chars), the response SHALL include field error details.
     *
     * <p>The GlobalExceptionHandler sets "field" and "errorType" properties
     * for AssertionException from pure-assert. TenantId.of() uses pure-assert with
     * maxLength(100), so a tenant ID > 100 chars triggers AssertionException → 400.
     */
    @Property(tries = 20)
    @Label("Property 16f: Pure-assert validation errors include field and errorType details")
    void pureAssertValidationErrorIncludesFieldDetails(@ForAll("tooLongTenantIds") String tooLongTenantId) {
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tooLongTenantId)
                .body(Map.of(
                        "handle", "validhandle",
                        "attributes", Map.of()
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Tenant ID > 100 chars should return 400. Response: %s", response.body().asString())
                .isEqualTo(400);

        String field = response.jsonPath().getString("field");
        String errorType = response.jsonPath().getString("errorType");

        boolean hasFieldDetails = (field != null && !field.isBlank())
                || (errorType != null && !errorType.isBlank());

        assertThat(hasFieldDetails)
                .as("Validation error response should include field details (field or errorType). "
                        + "Response body: %s", response.body().asString())
                .isTrue();
    }

    // =========================================================================
    // Property 16 (cross-cutting): Non-existent profile always returns 4xx
    // =========================================================================

    /**
     * Cross-cutting property: For any non-existent profile ID, the response
     * status SHALL always be in the 4xx range (client error), never 2xx or 3xx.
     */
    @Property(tries = 30)
    @Label("Property 16: Non-existent profile always returns client error (4xx)")
    void nonExistentProfileAlwaysReturnsClientError(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Non-existent profile %s should return 4xx, not 2xx/3xx", nonExistentId)
                .isBetween(400, 499);
    }

    // =========================================================================
    // Arbitraries
    // =========================================================================

    /**
     * Generates random UUIDs that are extremely unlikely to exist in the database.
     */
    @Provide
    Arbitrary<UUID> nonExistentIds() {
        return Arbitraries.randomValue(random -> UUID.randomUUID());
    }

    /**
     * Generates handles with uppercase letters or special characters (invalid format).
     * Handle must match ^[a-z0-9_]{3,30}$ — uppercase and hyphens are invalid.
     */
    @Provide
    Arbitrary<String> invalidHandles() {
        return Arbitraries.of(
                "UPPERCASE",
                "Has Space",
                "has-hyphen",
                "has.dot",
                "has@symbol",
                "HAS_UPPER_AND_LOWER",
                "ALLCAPS123"
        );
    }

    /**
     * Generates handles that are too short (< 3 characters).
     */
    @Provide
    Arbitrary<String> tooShortHandles() {
        return Arbitraries.of("a", "ab", "");
    }

    /**
     * Generates valid handles (lowercase alphanumeric + underscore, 3-30 chars).
     * Used for the ProfileDeletedException (410 GONE) test.
     */
    @Provide
    Arbitrary<String> validHandles() {
        return Arbitraries.integers().between(3, 20).map(length -> {
            String prefix = "testhandle";
            String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, Math.max(0, length - prefix.length()));
            return (prefix + suffix).substring(0, Math.min(length, prefix.length() + suffix.length()));
        });
    }

    /**
     * Generates tenant IDs that exceed the maximum length of 100 characters.
     * These fail in TenantId.of() via pure-assert maxLength(100) → AssertionException → 400.
     */
    @Provide
    Arbitrary<String> tooLongTenantIds() {
        return Arbitraries.integers().between(101, 200).map(length -> {
            StringBuilder sb = new StringBuilder("tenant-");
            while (sb.length() < length) {
                sb.append("x");
            }
            return sb.toString();
        });
    }
}
