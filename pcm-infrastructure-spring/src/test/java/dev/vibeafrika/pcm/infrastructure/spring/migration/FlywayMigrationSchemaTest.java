package dev.vibeafrika.pcm.infrastructure.spring.migration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-context Flyway migration schema validation.
 *
 * Applies all migrations (V1–V6) against a real postgres:15-alpine container
 * and asserts the resulting schema against the JPA entity definitions for all
 * four bounded contexts: Preference, Profile, Consent, and Segment.
 *
 * Three correctness properties are validated via @ParameterizedTest:
 *   Property 1 – every bounded-context table exists with its required prefix
 *   Property 2 – every non-nullable JPA column is present and NOT NULL in the DB
 *   Property 3 – every index declared in @Table annotations is present in the DB
 *
 */
@DisplayName("Flyway Migration Schema Validation — All Bounded Contexts")
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class FlywayMigrationSchemaTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_migration_test")
            .withUsername("pcm_user")
            .withPassword("pcm_password");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
    }

    @Autowired
    DataSource dataSource;

    @Autowired
    ApplicationContext applicationContext;

    // =========================================================================
    // Smoke — Flyway history 
    // =========================================================================

    @Test
    @DisplayName("flyway_schema_history has 6 rows, all successful")
    void flywayHistory_hasSixSuccessfulMigrations() throws Exception {
        try (Connection conn = dataSource.getConnection();
             var stmt = conn.createStatement();
             var rs = stmt.executeQuery(
                     "SELECT COUNT(*) AS total, " +
                     "SUM(CASE WHEN success THEN 1 ELSE 0 END) AS successful " +
                     "FROM flyway_schema_history")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getInt("total"))
                    .as("flyway_schema_history must contain exactly 6 migration rows")
                    .isEqualTo(6);
            assertThat(rs.getInt("successful"))
                    .as("All 6 migrations must have success = true")
                    .isEqualTo(6);
        }
    }

    // =========================================================================
    // Property 1 — table prefix invariant
    // =========================================================================

    /**
     * Every bounded-context table must exist with its prefix, and the
     * equivalent unprefixed name must NOT exist.
     *
     * Pairs: (prefixedName, unprefixedName | null if no unprefixed check needed)
     */
    static Stream<Arguments> prefixedTables() {
        return Stream.of(
                Arguments.of("preference_preferences", "preferences"),
                Arguments.of("preference_settings",    "settings"),
                Arguments.of("profile_profiles",       "profiles"),
                Arguments.of("consent_consents",       "consents"),
                Arguments.of("consent_events",         "events"),
                Arguments.of("segment_segments",       "segments"),
                Arguments.of("segment_tags",           "tags")
        );
    }

    @ParameterizedTest(name = "table ''{0}'' exists; ''{1}'' does not")
    @MethodSource("prefixedTables")
    @DisplayName("Property 1: bounded-context table exists with required prefix")
    void property1_tablePrefixInvariant(String prefixedName, String unprefixedName) throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();

            // Prefixed table must exist
            try (ResultSet rs = meta.getTables(null, "public", prefixedName, new String[]{"TABLE"})) {
                assertThat(rs.next())
                        .as("Table '%s' must exist", prefixedName)
                        .isTrue();
            }

            // Unprefixed table must NOT exist
            try (ResultSet rs = meta.getTables(null, "public", unprefixedName, new String[]{"TABLE"})) {
                assertThat(rs.next())
                        .as("Unprefixed table '%s' must NOT exist; use '%s'", unprefixedName, prefixedName)
                        .isFalse();
            }
        }
    }

    // =========================================================================
    // Property 2 — non-nullable column invariant
    // =========================================================================

    /**
     * (table, column, expectNullable) triples derived from JPA entity definitions.
     * Only non-nullable columns (nullable=false) are listed; nullable columns are
     * omitted because the property only asserts NOT NULL constraints.
     */
    static Stream<Arguments> nonNullableColumns() {
        return Stream.of(
                // preference_preferences
                Arguments.of("preference_preferences", "id",           false),
                Arguments.of("preference_preferences", "tenant_id",    false),
                Arguments.of("preference_preferences", "profile_id",   false),
                Arguments.of("preference_preferences", "last_updated", false),
                Arguments.of("preference_preferences", "deleted",      false),
                Arguments.of("preference_preferences", "created_at",   false),
                Arguments.of("preference_preferences", "updated_at",   false),

                // preference_settings (ElementCollection — FK is NOT NULL)
                Arguments.of("preference_settings", "preference_id", false),
                Arguments.of("preference_settings", "setting_key",   false),

                // profile_profiles
                Arguments.of("profile_profiles", "id",         false),
                Arguments.of("profile_profiles", "tenant_id",  false),
                Arguments.of("profile_profiles", "handle",     false),
                Arguments.of("profile_profiles", "created_at", false),
                Arguments.of("profile_profiles", "updated_at", false),
                Arguments.of("profile_profiles", "deleted",    false),

                // consent_consents
                Arguments.of("consent_consents", "id",         false),
                Arguments.of("consent_consents", "profile_id", false),
                Arguments.of("consent_consents", "tenant_id",  false),
                Arguments.of("consent_consents", "purpose",    false),
                Arguments.of("consent_consents", "scope",      false),
                Arguments.of("consent_consents", "status",     false),
                Arguments.of("consent_consents", "created_at", false),
                Arguments.of("consent_consents", "updated_at", false),

                // consent_events
                Arguments.of("consent_events", "id",         false),
                Arguments.of("consent_events", "consent_id", false),
                Arguments.of("consent_events", "status",     false),
                Arguments.of("consent_events", "timestamp",  false),

                // segment_segments
                Arguments.of("segment_segments", "id",           false),
                Arguments.of("segment_segments", "tenant_id",    false),
                Arguments.of("segment_segments", "profile_id",   false),
                Arguments.of("segment_segments", "last_updated", false),
                Arguments.of("segment_segments", "created_at",   false),
                Arguments.of("segment_segments", "updated_at",   false),

                // segment_tags (ElementCollection — FK is NOT NULL)
                Arguments.of("segment_tags", "segment_id", false),
                Arguments.of("segment_tags", "tag",        false)
        );
    }

    @ParameterizedTest(name = "''{0}''.{1} nullable={2}")
    @MethodSource("nonNullableColumns")
    @DisplayName("Property 2: non-nullable JPA column is NOT NULL in the database")
    void property2_nonNullableColumnInvariant(String table, String column, boolean expectNullable) throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getColumns(null, "public", table, column)) {
                assertThat(rs.next())
                        .as("Column '%s.%s' must exist", table, column)
                        .isTrue();
                // NULLABLE: 0 = columnNoNulls, 1 = columnNullable
                int nullable = rs.getInt("NULLABLE");
                if (expectNullable) {
                    assertThat(nullable)
                            .as("Column '%s.%s' should be nullable", table, column)
                            .isEqualTo(DatabaseMetaData.columnNullable);
                } else {
                    assertThat(nullable)
                            .as("Column '%s.%s' should be NOT NULL", table, column)
                            .isEqualTo(DatabaseMetaData.columnNoNulls);
                }
            }
        }
    }

    // =========================================================================
    // Property 3 — index presence invariant 
    // =========================================================================

    /**
     * (table, indexName) pairs derived from @Table(indexes = {...}) annotations
     * across all four bounded-context JPA entities.
     */
    static Stream<Arguments> declaredIndexes() {
        return Stream.of(
                // PreferenceJpaEntity
                Arguments.of("preference_preferences", "idx_preference_tenant"),
                Arguments.of("preference_preferences", "idx_preference_profile"),
                Arguments.of("preference_preferences", "idx_preference_tenant_profile"),

                // ProfileJpaEntity
                Arguments.of("profile_profiles", "idx_profile_tenant"),
                Arguments.of("profile_profiles", "idx_profile_handle"),
                Arguments.of("profile_profiles", "idx_profile_handle_blind_index"),
                Arguments.of("profile_profiles", "idx_profile_tenant_id"),

                // ConsentJpaEntity
                Arguments.of("consent_consents", "idx_consent_profile"),
                Arguments.of("consent_consents", "idx_consent_tenant"),
                Arguments.of("consent_consents", "idx_consent_purpose"),
                Arguments.of("consent_consents", "idx_consent_status"),
                Arguments.of("consent_consents", "idx_consent_tenant_profile"),

                // ConsentEventJpaEntity
                Arguments.of("consent_events", "idx_consent_events_consent"),
                Arguments.of("consent_events", "idx_consent_events_timestamp"),

                // SegmentJpaEntity
                Arguments.of("segment_segments", "idx_segment_tenant"),
                Arguments.of("segment_segments", "idx_segment_profile"),
                Arguments.of("segment_segments", "idx_segment_tenant_profile")
        );
    }

    @ParameterizedTest(name = "index ''{1}'' on ''{0}''")
    @MethodSource("declaredIndexes")
    @DisplayName("Property 3: @Table-declared index is present in the database")
    void property3_indexPresenceInvariant(String table, String indexName) throws Exception {
        Set<String> indexes = getIndexNames(table);
        assertThat(indexes)
                .as("Index '%s' must exist on table '%s'", indexName, table)
                .contains(indexName);
    }

    // =========================================================================
    // Example — V6 blind index column
    // =========================================================================

    @Test
    @DisplayName("handle_blind_index column is present in profile_profiles (V6)")
    void v6_handleBlindIndexColumnPresent() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getColumns(null, "public", "profile_profiles", "handle_blind_index")) {
                assertThat(rs.next())
                        .as("Column 'handle_blind_index' must exist in profile_profiles (added by V6)")
                        .isTrue();
            }
        }
    }

    // =========================================================================
    // Example — Application context loads 
    // =========================================================================

    @Test
    @DisplayName("Application context loads without SchemaManagementException")
    void applicationContext_loadsSuccessfully() {
        assertThat(applicationContext)
                .as("ApplicationContext must not be null — context load implies ddl-auto=validate passed")
                .isNotNull();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private Set<String> getIndexNames(String table) throws Exception {
        Set<String> names = new HashSet<>();
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getIndexInfo(null, "public", table, false, false)) {
                while (rs.next()) {
                    String name = rs.getString("INDEX_NAME");
                    if (name != null) {
                        names.add(name.toLowerCase());
                    }
                }
            }
        }
        return names;
    }
}
