package dev.vibeafrika.pcm.infrastructure.spring.preference;

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
 * Property-based tests for exception translation in the Spring Boot infrastructure layer.
 *
 * <p><b>Property 16: Infrastructure Translates Domain Exceptions</b>
 *
 * <p>Verifies that the {@code GlobalExceptionHandler} correctly translates domain exceptions
 * into RFC 7807 Problem Details HTTP responses with appropriate status codes and content-type.
 *
 * <p>Sub-properties tested:
 * <ul>
 *   <li>16a: PreferenceNotFoundException → 404 NOT_FOUND</li>
 *   <li>16b: Domain validation exceptions (PreferenceValidationException) → 400 BAD_REQUEST</li>
 *   <li>16c: Error response content-type is "application/problem+json"</li>
 *   <li>16d: Error response contains required RFC 7807 fields (type, title, status, detail)</li>
 *   <li>16e: Validation errors include field error details (for pure-assert exceptions)</li>
 * </ul>
 *
 * <p>Implementation note: jqwik runs @Property tests in its own engine, separate from JUnit 5.
 * Spring's @SpringBootTest and @LocalServerPort injection are JUnit 5 features and do not work
 * with jqwik. Instead, this test uses jqwik's @BeforeContainer lifecycle to start a Spring Boot
 * application context with Testcontainers, capturing the server port statically.
 */
class ExceptionTranslationPropertyTest {

    private static final String TENANT_ID = "tenant-exception-test";
    private static final String BASE_PATH = "/api/v1/preferences";

    // Static state shared across all @Property methods
    private static PostgreSQLContainer<?> postgres;
    private static ConfigurableApplicationContext springContext;
    private static int serverPort;

    /**
     * Start Testcontainers PostgreSQL and Spring Boot application once before all properties.
     * Uses jqwik's @BeforeContainer lifecycle which runs before any @Property method.
     */
    @BeforeContainer
    static void startInfrastructure() {
        // Start PostgreSQL container
        postgres = new PostgreSQLContainer<>("postgres:15-alpine")
                .withDatabaseName("pcm_test")
                .withUsername("pcm_user")
                .withPassword("pcm_password");
        postgres.start();

        // Set system properties BEFORE starting Spring Boot so they override application.yml.
        // System properties have the highest priority in Spring's property resolution order.
        System.setProperty("spring.datasource.url", postgres.getJdbcUrl());
        System.setProperty("spring.datasource.username", postgres.getUsername());
        System.setProperty("spring.datasource.password", postgres.getPassword());
        System.setProperty("server.port", "0");

        // Start Spring Boot application with the test profile
        springContext = new SpringApplicationBuilder(PcmApplication.class)
                .profiles("test")
                .run();

        // Capture the actual port assigned by the embedded server
        serverPort = Integer.parseInt(
                springContext.getEnvironment().getProperty("local.server.port", "8080"));

        // Configure RestAssured base URI
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
        // Clean up system properties
        System.clearProperty("spring.datasource.url");
        System.clearProperty("spring.datasource.username");
        System.clearProperty("spring.datasource.password");
        System.clearProperty("server.port");
    }

    // =========================================================================
    // Property 16a: PreferenceNotFoundException → 404 NOT_FOUND
    // =========================================================================

    /**
     * Property 16a: For any random UUID that does not correspond to an existing preference,
     * a GET request SHALL return HTTP 404 NOT_FOUND.
     *
     * <p>The GlobalExceptionHandler maps PreferenceNotFoundException → 404.
     */
    @Property(tries = 20)
    @Label("Property 16a: Any non-existent preference ID returns 404 NOT_FOUND")
    void nonExistentPreferenceIdReturns404(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Non-existent preference %s should return 404", nonExistentId)
                .isEqualTo(404);
    }

    // =========================================================================
    // Property 16b: Domain validation exceptions → 400 BAD_REQUEST
    // =========================================================================

    /**
     * Property 16b: For any POST request with a tenant ID exceeding the maximum length
     * (100 chars), the response SHALL be HTTP 400 BAD_REQUEST.
     *
     * <p>The TenantId value object uses pure-assert maxLength(100), so a tenant ID > 100 chars
     * triggers AssertionException which the GlobalExceptionHandler maps to 400.
     */
    @Property(tries = 20)
    @Label("Property 16b: Tenant ID exceeding max length triggers 400 BAD_REQUEST")
    void tooLongTenantIdReturns400(@ForAll("validProfileIds") UUID profileId,
                                   @ForAll("tooLongTenantIds") String tooLongTenantId) {
        // A tenant ID > 100 chars passes DTO validation (only checks blank)
        // but fails in TenantId.of() via pure-assert maxLength(100) → AssertionException → 400
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tooLongTenantId)
                .body(Map.of(
                        "tenantId", tooLongTenantId,
                        "profileId", profileId.toString(),
                        "settings", Map.of("key", "value")
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Tenant ID > 100 chars should return 400 for profileId %s", profileId)
                .isEqualTo(400);
    }

    /**
     * Property 16b (variant): For any DELETE request on a non-existent preference,
     * the response SHALL be HTTP 404 NOT_FOUND (domain exception translation).
     */
    @Property(tries = 20)
    @Label("Property 16b: Delete non-existent preference returns 404 NOT_FOUND")
    void deleteNonExistentPreferenceReturns404(@ForAll("nonExistentIds") UUID preferenceId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .delete(BASE_PATH + "/" + preferenceId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Delete non-existent preference %s should return 404", preferenceId)
                .isEqualTo(404);
    }

    // =========================================================================
    // Property 16c: Error response content-type is "application/problem+json"
    // =========================================================================

    /**
     * Property 16c: For any 404 error response (non-existent preference),
     * the content-type SHALL be "application/problem+json".
     */
    @Property(tries = 20)
    @Label("Property 16c: 404 error response content-type is application/problem+json")
    void notFoundResponseHasProblemJsonContentType(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(404);

        String contentType = response.contentType();
        assertThat(contentType)
                .as("404 response for %s should have application/problem+json content-type", nonExistentId)
                .contains("application/problem+json");
    }

    /**
     * Property 16c (variant): For any 400 error response (validation failure),
     * the content-type SHALL be "application/problem+json".
     */
    @Property(tries = 20)
    @Label("Property 16c: 400 error response content-type is application/problem+json")
    void validationErrorResponseHasProblemJsonContentType(@ForAll("validProfileIds") UUID profileId,
                                                          @ForAll("tooLongTenantIds") String tooLongTenantId) {
        // Tenant ID > 100 chars triggers pure-assert AssertionException → 400
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tooLongTenantId)
                .body(Map.of(
                        "tenantId", tooLongTenantId,
                        "profileId", profileId.toString(),
                        "settings", Map.of("key", "value")
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(400);

        String contentType = response.contentType();
        assertThat(contentType)
                .as("400 response should have application/problem+json content-type")
                .contains("application/problem+json");
    }

    // =========================================================================
    // Property 16d: RFC 7807 required fields present in error response
    // =========================================================================

    /**
     * Property 16d: For any 404 error response, the body SHALL contain
     * the required RFC 7807 fields: type, title, status, detail.
     */
    @Property(tries = 20)
    @Label("Property 16d: 404 response contains required RFC 7807 fields")
    void notFoundResponseContainsRfc7807Fields(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(404);

        // RFC 7807 required fields
        assertThat(response.jsonPath().getString("type"))
                .as("RFC 7807 'type' field must be present")
                .isNotNull()
                .isNotBlank();

        assertThat(response.jsonPath().getString("title"))
                .as("RFC 7807 'title' field must be present")
                .isNotNull()
                .isNotBlank();

        assertThat(response.jsonPath().getInt("status"))
                .as("RFC 7807 'status' field must equal 404")
                .isEqualTo(404);

        assertThat(response.jsonPath().getString("detail"))
                .as("RFC 7807 'detail' field must be present")
                .isNotNull()
                .isNotBlank();
    }

    /**
     * Property 16d (variant): For any 400 validation error response, the body SHALL contain
     * the required RFC 7807 fields: type, title, status, detail.
     */
    @Property(tries = 20)
    @Label("Property 16d: 400 response contains required RFC 7807 fields")
    void validationErrorResponseContainsRfc7807Fields(@ForAll("validProfileIds") UUID profileId,
                                                      @ForAll("tooLongTenantIds") String tooLongTenantId) {
        // Tenant ID > 100 chars triggers pure-assert AssertionException → 400
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tooLongTenantId)
                .body(Map.of(
                        "tenantId", tooLongTenantId,
                        "profileId", profileId.toString(),
                        "settings", Map.of("key", "value")
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode()).isEqualTo(400);

        assertThat(response.jsonPath().getString("type"))
                .as("RFC 7807 'type' field must be present in 400 response")
                .isNotNull()
                .isNotBlank();

        assertThat(response.jsonPath().getString("title"))
                .as("RFC 7807 'title' field must be present in 400 response")
                .isNotNull()
                .isNotBlank();

        assertThat(response.jsonPath().getInt("status"))
                .as("RFC 7807 'status' field must equal 400")
                .isEqualTo(400);

        assertThat(response.jsonPath().getString("detail"))
                .as("RFC 7807 'detail' field must be present in 400 response")
                .isNotNull()
                .isNotBlank();
    }

    // =========================================================================
    // Property 16e: Pure-assert validation errors include field error details
    // =========================================================================

    /**
     * Property 16e: For any pure-assert validation error triggered by a tenant ID exceeding
     * the maximum length (100 chars), the response SHALL include field error details.
     *
     * <p>The GlobalExceptionHandler sets "field" and "errorType" properties
     * for AssertionException from pure-assert. TenantId.of() uses pure-assert with
     * maxLength(100), so a tenant ID > 100 chars triggers AssertionException → 400.
     */
    @Property(tries = 20)
    @Label("Property 16e: Pure-assert validation errors include field and errorType details")
    void pureAssertValidationErrorIncludesFieldDetails(@ForAll("validProfileIds") UUID profileId,
                                                       @ForAll("tooLongTenantIds") String tooLongTenantId) {
        // A tenant ID > 100 chars passes DTO validation (only checks blank)
        // but fails in TenantId.of() via pure-assert maxLength(100) → AssertionException → 400
        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tooLongTenantId)
                .body(Map.of(
                        "tenantId", tooLongTenantId,
                        "profileId", profileId.toString(),
                        "settings", Map.of("key", "value")
                ))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Tenant ID > 100 chars should return 400. Response: %s", response.body().asString())
                .isEqualTo(400);

        // The GlobalExceptionHandler includes "field" and "errorType" for pure-assert exceptions
        String field = response.jsonPath().getString("field");
        String errorType = response.jsonPath().getString("errorType");

        // At least one of these should be present for pure-assert validation errors
        boolean hasFieldDetails = (field != null && !field.isBlank())
                || (errorType != null && !errorType.isBlank());

        assertThat(hasFieldDetails)
                .as("Validation error response should include field details (field or errorType). "
                        + "Response body: %s", response.body().asString())
                .isTrue();
    }

    // =========================================================================
    // Property 16 (cross-cutting): Non-existent preference always returns 4xx
    // =========================================================================

    /**
     * Cross-cutting property: For any non-existent preference ID, the response
     * status SHALL always be in the 4xx range (client error), never 2xx or 3xx.
     */
    @Property(tries = 30)
    @Label("Property 16: Non-existent preference always returns client error (4xx)")
    void nonExistentPreferenceAlwaysReturnsClientError(@ForAll("nonExistentIds") UUID nonExistentId) {
        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", TENANT_ID)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Non-existent preference %s should return 4xx, not 2xx/3xx", nonExistentId)
                .isBetween(400, 499);
    }

    // =========================================================================
    // Arbitraries
    // =========================================================================

    /**
     * Generates random UUIDs that are extremely unlikely to exist in the database.
     * Since the database is fresh per test run, any random UUID will be non-existent.
     */
    @Provide
    Arbitrary<UUID> nonExistentIds() {
        return Arbitraries.randomValue(random -> UUID.randomUUID());
    }

    /**
     * Generates random valid profile UUIDs for use in request bodies.
     */
    @Provide
    Arbitrary<UUID> validProfileIds() {
        return Arbitraries.randomValue(random -> UUID.randomUUID());
    }

    /**
     * Generates tenant IDs that exceed the maximum length of 100 characters.
     * These will pass DTO validation (which only checks for blank) but fail
     * in TenantId.of() via pure-assert maxLength(100) → AssertionException → 400.
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
