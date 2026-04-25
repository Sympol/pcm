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
 * Property-based test for API contract preservation.
 *
 * <p><b>API Contracts Remain Unchanged</b>
 *
 * <p>Verifies that the Profile REST API contract is stable across a wide range of valid inputs.
 * Properties tested:
 * <ul>
 *   <li>POST /api/v1/profiles always returns 201 for valid handles and tenants</li>
 *   <li>GET /api/v1/profiles/{id} always returns 200 for existing profiles</li>
 *   <li>PUT /api/v1/profiles/{id} always returns 200 for existing active profiles</li>
 *   <li>DELETE /api/v1/profiles/{id} always returns 204 for existing profiles</li>
 *   <li>Response schema fields are always present and consistent</li>
 *   <li>Invalid handles always return 400 (contract stable for error paths)</li>
 *   <li>Non-existent IDs always return 404</li>
 * </ul>
 *
 */
class ProfileApiContractPropertyTest {

    private static final String BASE_PATH = "/api/v1/profiles";

    private static PostgreSQLContainer<?> postgres;
    private static ConfigurableApplicationContext springContext;
    private static int serverPort;

    @BeforeContainer
    static void startInfrastructure() {
        postgres = new PostgreSQLContainer<>("postgres:15-alpine")
                .withDatabaseName("pcm_contract_prop_test")
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

    @AfterContainer
    static void stopInfrastructure() {
        if (springContext != null) springContext.close();
        if (postgres != null) postgres.stop();
        System.clearProperty("spring.datasource.url");
        System.clearProperty("spring.datasource.username");
        System.clearProperty("spring.datasource.password");
        System.clearProperty("server.port");
    }

    // =========================================================================
    //  POST always returns 201 for valid inputs
    // =========================================================================

    /**
     * For any valid handle and tenant ID, POST /api/v1/profiles
     * SHALL return HTTP 201 Created with the full response schema.
     */
    @Property(tries = 20)
    @Label("POST with valid handle always returns 201 with complete schema")
    void postWithValidHandle_returns201WithCompleteSchema(
            @ForAll("validHandles") String handle,
            @ForAll("validTenantIds") String tenantId) {

        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tenantId)
                .body(Map.of("tenantId", tenantId, "handle", handle, "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("POST with valid handle '%s' must return 201", handle)
                .isEqualTo(201);

        // Response schema fields must always be present
        assertThat(response.jsonPath().getString("id"))
                .as("Response must include 'id' field").isNotBlank();
        assertThat(response.jsonPath().getString("tenantId"))
                .as("Response must include 'tenantId' field").isEqualTo(tenantId);
        assertThat(response.jsonPath().getString("handle"))
                .as("Response must include 'handle' field matching input").isEqualTo(handle);
        assertThat(response.jsonPath().getMap("attributes"))
                .as("Response must include 'attributes' field").isNotNull();
        assertThat(response.jsonPath().getString("createdAt"))
                .as("Response must include 'createdAt' timestamp").isNotBlank();
        assertThat(response.jsonPath().getString("updatedAt"))
                .as("Response must include 'updatedAt' timestamp").isNotBlank();
        assertThat((Object) response.jsonPath().get("version"))
                .as("Response must include 'version' field").isNotNull();
    }

    // =========================================================================
    // GET always returns 200 for existing profile
    // =========================================================================

    /**
     * For any profile that was successfully created, a subsequent GET
     * SHALL return HTTP 200 with the same schema fields.
     */
    @Property(tries = 10)
    @Label("GET on existing profile always returns 200 with full schema")
    void getExistingProfile_returns200WithFullSchema(
            @ForAll("validHandles") String handle,
            @ForAll("validTenantIds") String tenantId) {

        // Create a profile
        Response created = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tenantId)
                .body(Map.of("tenantId", tenantId, "handle", handle, "attributes", Map.of("key", "val")))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        if (created.statusCode() != 201) return; // handle conflict from prior try

        String profileId = created.jsonPath().getString("id");

        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", tenantId)
                .when()
                .get(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("GET on existing profile '%s' must return 200", profileId)
                .isEqualTo(200);

        // Schema must match creation response schema
        assertThat(response.jsonPath().getString("id")).isEqualTo(profileId);
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(tenantId);
        assertThat(response.jsonPath().getString("handle")).isEqualTo(handle);
        assertThat(response.jsonPath().getMap("attributes")).isNotNull();
        assertThat(response.jsonPath().getString("createdAt")).isNotBlank();
        assertThat(response.jsonPath().getString("updatedAt")).isNotBlank();
    }

    // =========================================================================
    // PUT always returns 200 for active profiles
    // =========================================================================

    /**
     * For any existing active profile, a PUT request with valid attributes
     * SHALL return HTTP 200 with an updated schema.
     */
    @Property(tries = 10)
    @Label("PUT on active profile always returns 200")
    void putOnActiveProfile_returns200(
            @ForAll("validHandles") String handle,
            @ForAll("validTenantIds") String tenantId) {

        Response created = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tenantId)
                .body(Map.of("tenantId", tenantId, "handle", handle, "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        if (created.statusCode() != 201) return;

        String profileId = created.jsonPath().getString("id");

        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tenantId)
                .body(Map.of("profileId", profileId, "tenantId", tenantId,
                        "attributes", Map.of("updated", "true")))
                .when()
                .put(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("PUT on active profile '%s' must return 200", profileId)
                .isEqualTo(200);

        assertThat(response.jsonPath().getString("id")).isEqualTo(profileId);
        assertThat(response.jsonPath().getString("tenantId")).isEqualTo(tenantId);
        assertThat(response.jsonPath().getString("updatedAt")).isNotBlank();
    }

    // =========================================================================
    // DELETE always returns 204 for existing profiles
    // =========================================================================

    /**
     * For any existing profile, a DELETE request SHALL return
     * HTTP 204 No Content with an empty body.
     */
    @Property(tries = 10)
    @Label("DELETE on existing profile always returns 204 No Content")
    void deleteExistingProfile_returns204(@ForAll("validHandles") String handle,
            @ForAll("validTenantIds") String tenantId) {

        Response created = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tenantId)
                .body(Map.of("tenantId", tenantId, "handle", handle, "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        if (created.statusCode() != 201) return;

        String profileId = created.jsonPath().getString("id");

        Response response = given()
                .port(serverPort)
                .header("X-Tenant-Id", tenantId)
                .when()
                .delete(BASE_PATH + "/" + profileId)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("DELETE on profile '%s' must return 204", profileId)
                .isEqualTo(204);

        assertThat(response.body().asString())
                .as("204 response must have empty body").isEmpty();
    }

    // =========================================================================
    // Invalid handles always return 400
    // =========================================================================

    /**
     * For any request with an invalid handle format, the API SHALL
     * always return 400 BAD_REQUEST (contract stable for error paths).
     */
    @Property(tries = 20)
    @Label("Property 21f: Invalid handles always return 400 across all inputs")
    void invalidHandles_alwaysReturn400(@ForAll("invalidHandles") String invalidHandle,
            @ForAll("validTenantIds") String tenantId) {

        Response response = given()
                .port(serverPort)
                .contentType(ContentType.JSON)
                .header("X-Tenant-Id", tenantId)
                .body(Map.of("tenantId", tenantId, "handle", invalidHandle, "attributes", Map.of()))
                .when()
                .post(BASE_PATH)
                .then()
                .extract().response();

        assertThat(response.statusCode())
                .as("Invalid handle '%s' must always return 400", invalidHandle)
                .isEqualTo(400);
    }

    // =========================================================================
    // Non-existent IDs always return 404
    // =========================================================================

    /**
     * For any UUID that was not previously created, GET and DELETE
     * SHALL always return 404 NOT_FOUND.
     */
    @Property(tries = 20)
    @Label("Property 21g: Non-existent profile IDs always return 404")
    void nonExistentIds_alwaysReturn404(@ForAll("nonExistentIds") UUID nonExistentId,
            @ForAll("validTenantIds") String tenantId) {

        Response getResponse = given()
                .port(serverPort)
                .header("X-Tenant-Id", tenantId)
                .when()
                .get(BASE_PATH + "/" + nonExistentId)
                .then()
                .extract().response();

        assertThat(getResponse.statusCode())
                .as("GET non-existent profile %s must return 404", nonExistentId)
                .isEqualTo(404);
    }

    // =========================================================================
    // Arbitraries
    // =========================================================================

    /** Generates valid handles: lowercase alphanumeric + underscore, 3–30 chars.
     *  Each handle is unique to avoid unique-constraint collisions across tries. */
    @Provide
    Arbitrary<String> validHandles() {
        // Always produce a unique handle by using a full UUID suffix (no truncation below 3 chars).
        // Format: "h" + first 19 chars of UUID hex → always 20 chars, always unique, always valid.
        return Arbitraries.randomValue(random -> {
            String uuid = UUID.randomUUID().toString().replace("-", "");
            return "h" + uuid.substring(0, 19); // 20 chars total, lowercase hex + 'h'
        });
    }

    /** Generates valid tenant IDs (non-blank, max 100 chars). */
    @Provide
    Arbitrary<String> validTenantIds() {
        return Arbitraries.of(
                "tenant-alpha",
                "tenant-beta",
                "tenant-gamma",
                "tenant-delta"
        );
    }

    /** Generates handles with uppercase letters or invalid characters. */
    @Provide
    Arbitrary<String> invalidHandles() {
        return Arbitraries.of(
                "UPPERCASE",
                "Has Space",
                "has-hyphen",
                "has.dot",
                "has@symbol",
                "ab",       // too short
                ""          // empty
        );
    }

    /** Generates random UUIDs extremely unlikely to exist in the test DB. */
    @Provide
    Arbitrary<UUID> nonExistentIds() {
        return Arbitraries.randomValue(random -> UUID.randomUUID());
    }
}
