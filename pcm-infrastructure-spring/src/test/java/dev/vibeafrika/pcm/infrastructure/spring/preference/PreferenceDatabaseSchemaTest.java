package dev.vibeafrika.pcm.infrastructure.spring.preference;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Database schema validation test for the Preference context.
 *
 * Verifies that:
 * - Flyway migrations ran successfully (V1 present in flyway_schema_history)
 * - Required tables exist with the preference_ prefix
 * - Required columns exist in preference_preferences
 * - Key indexes exist
 * - Unique constraint on profile_id exists
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class PreferenceDatabaseSchemaTest {

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

    @Autowired
    DataSource dataSource;

    @Autowired
    JdbcTemplate jdbcTemplate;

    // -------------------------------------------------------------------------
    // 1. Flyway migration validation
    // -------------------------------------------------------------------------

    @Test
    void flywayMigration_V1_isPresentAndSuccessful() {
        List<Boolean> results = jdbcTemplate.query(
                "SELECT success FROM flyway_schema_history WHERE version = '1'",
                (rs, rowNum) -> rs.getBoolean("success")
        );

        assertThat(results)
                .as("V1 migration should be present in flyway_schema_history")
                .isNotEmpty();

        assertThat(results.get(0))
                .as("V1 migration should be marked as successful")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // 2. Table existence
    // -------------------------------------------------------------------------

    @Test
    void table_preferencePreferences_exists() throws Exception {
        assertThat(tableExists("preference_preferences"))
                .as("Table preference_preferences should exist")
                .isTrue();
    }

    @Test
    void table_preferenceSettings_exists() throws Exception {
        assertThat(tableExists("preference_settings"))
                .as("Table preference_settings should exist")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // 3. Column validation for preference_preferences
    // -------------------------------------------------------------------------

    @Test
    void preferencePreferences_hasAllRequiredColumns() throws Exception {
        List<String> columns = getColumns("preference_preferences");

        assertThat(columns)
                .as("preference_preferences should have all required columns")
                .contains("id", "tenant_id", "profile_id", "last_updated",
                          "deleted", "created_at", "updated_at", "version");
    }

    // -------------------------------------------------------------------------
    // 4. Index validation
    // -------------------------------------------------------------------------

    @Test
    void index_idx_preference_tenant_exists() throws Exception {
        assertThat(indexExists("preference_preferences", "idx_preference_tenant"))
                .as("Index idx_preference_tenant should exist on preference_preferences")
                .isTrue();
    }

    @Test
    void index_idx_preference_profile_exists() throws Exception {
        assertThat(indexExists("preference_preferences", "idx_preference_profile"))
                .as("Index idx_preference_profile should exist on preference_preferences")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // 5. Unique constraint on profile_id
    // -------------------------------------------------------------------------

    @Test
    void uniqueConstraint_uk_preference_profile_exists() throws Exception {
        // The unique constraint is backed by a unique index in PostgreSQL
        assertThat(uniqueIndexExists("preference_preferences", "uk_preference_profile"))
                .as("Unique constraint uk_preference_profile should exist on preference_preferences")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // 6. Table prefix validation
    // -------------------------------------------------------------------------

    @Test
    void tables_usePreferencePrefix() throws Exception {
        assertThat(tableExists("preference_preferences"))
                .as("Table should use 'preference_' prefix, not just 'preferences'")
                .isTrue();

        assertThat(tableExists("preferences"))
                .as("Table 'preferences' without prefix should NOT exist")
                .isFalse();

        assertThat(tableExists("preference_settings"))
                .as("Table should use 'preference_' prefix, not just 'settings'")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private boolean tableExists(String tableName) throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getTables(null, null, tableName, new String[]{"TABLE"})) {
                return rs.next();
            }
        }
    }

    private List<String> getColumns(String tableName) throws Exception {
        List<String> columns = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getColumns(null, null, tableName, null)) {
                while (rs.next()) {
                    columns.add(rs.getString("COLUMN_NAME").toLowerCase());
                }
            }
        }
        return columns;
    }

    private boolean indexExists(String tableName, String indexName) throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getIndexInfo(null, null, tableName, false, false)) {
                while (rs.next()) {
                    String name = rs.getString("INDEX_NAME");
                    if (indexName.equalsIgnoreCase(name)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean uniqueIndexExists(String tableName, String indexName) throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            // unique=true filters to only unique indexes
            try (ResultSet rs = meta.getIndexInfo(null, null, tableName, true, false)) {
                while (rs.next()) {
                    String name = rs.getString("INDEX_NAME");
                    if (indexName.equalsIgnoreCase(name)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
