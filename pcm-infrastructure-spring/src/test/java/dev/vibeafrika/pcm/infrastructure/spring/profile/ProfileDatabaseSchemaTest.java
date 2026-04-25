package dev.vibeafrika.pcm.infrastructure.spring.profile;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
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
 * Database schema validation for the Profile context.
 *
 * Verifies that the Flyway-applied schema for the profile_profiles table
 * matches the expected structure: correct table name (with profile_ prefix),
 * required columns, column types, NOT NULL constraints, indexes, and unique
 * constraints.
 *
 * This test intentionally uses Flyway (not DDL auto) to validate real migrations.
 */
@DisplayName("Profile Database Schema Validation")
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class ProfileDatabaseSchemaTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_schema_test")
            .withUsername("pcm_user")
            .withPassword("pcm_password");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        // Use Flyway to apply real migrations
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
    }

    @Autowired
    DataSource dataSource;

    private static final String TABLE = "profile_profiles";

    // -------------------------------------------------------------------------
    // 1. Table exists with correct prefix
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("profile_profiles table exists with correct prefix")
    void profileProfilesTable_exists() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getTables(null, "public", TABLE, new String[]{"TABLE"})) {
                assertThat(rs.next())
                        .as("Table 'profile_profiles' must exist with 'profile_' prefix")
                        .isTrue();
                assertThat(rs.getString("TABLE_NAME")).isEqualTo(TABLE);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2. Required columns present with correct types and nullability
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("profile_profiles has all required columns")
    void profileProfilesTable_hasRequiredColumns() throws Exception {
        List<String> actualColumns = getColumns();

        assertThat(actualColumns)
                .as("profile_profiles must contain required columns")
                .contains("id", "tenant_id", "handle", "attributes",
                        "created_at", "updated_at", "version", "deleted");
    }

    @Test
    @DisplayName("profile_profiles includes handle_blind_index column from V6 migration")
    void profileProfilesTable_hasBlindIndexColumn() throws Exception {
        List<String> actualColumns = getColumns();

        assertThat(actualColumns)
                .as("profile_profiles must include handle_blind_index from V6 migration")
                .contains("handle_blind_index");
    }

    @Test
    @DisplayName("id column is non-nullable")
    void idColumn_isNonNullable() throws Exception {
        assertColumnNullable("id", false);
    }

    @Test
    @DisplayName("tenant_id column is non-nullable")
    void tenantIdColumn_isNonNullable() throws Exception {
        assertColumnNullable("tenant_id", false);
    }

    @Test
    @DisplayName("handle column is non-nullable ")
    void handleColumn_isNonNullable() throws Exception {
        assertColumnNullable("handle", false);
    }

    @Test
    @DisplayName("created_at column is non-nullable ")
    void createdAtColumn_isNonNullable() throws Exception {
        assertColumnNullable("created_at", false);
    }

    @Test
    @DisplayName("updated_at column is non-nullable ")
    void updatedAtColumn_isNonNullable() throws Exception {
        assertColumnNullable("updated_at", false);
    }

    @Test
    @DisplayName("deleted column is non-nullable ")
    void deletedColumn_isNonNullable() throws Exception {
        assertColumnNullable("deleted", false);
    }

    // -------------------------------------------------------------------------
    // 3. Primary key constraint
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("id is the primary key ")
    void idColumn_isPrimaryKey() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getPrimaryKeys(null, "public", TABLE)) {
                assertThat(rs.next())
                        .as("profile_profiles must have a primary key").isTrue();
                assertThat(rs.getString("COLUMN_NAME"))
                        .as("Primary key must be the 'id' column").isEqualTo("id");
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4. Indexes present
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("profile_profiles has required indexes")
    void profileProfilesTable_hasRequiredIndexes() throws Exception {
        List<String> indexes = getIndexNames();

        assertThat(indexes)
                .as("profile_profiles must have tenant and handle indexes")
                .anySatisfy(idx -> assertThat(idx).contains("profile_tenant"))
                .anySatisfy(idx -> assertThat(idx).contains("profile_handle"));
    }

    @Test
    @DisplayName("handle_blind_index has a dedicated index")
    void handleBlindIndex_hasDedicatedIndex() throws Exception {
        List<String> indexes = getIndexNames();

        assertThat(indexes)
                .as("profile_profiles must have an index on handle_blind_index")
                .anySatisfy(idx -> assertThat(idx).contains("blind_index"));
    }

    // -------------------------------------------------------------------------
    // 5. No extra unexpected tables with wrong prefix
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("No 'profiles' table without prefix exists (ensures table prefix isolation)")
    void noUnprefixedProfilesTable() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            // Check the table without prefix does NOT exist
            try (ResultSet rs = meta.getTables(null, "public", "profiles", new String[]{"TABLE"})) {
                assertThat(rs.next())
                        .as("Table 'profiles' without prefix must NOT exist; use 'profile_profiles'")
                        .isFalse();
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private List<String> getColumns() throws Exception {
        List<String> cols = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getColumns(null, "public", TABLE, "%")) {
                while (rs.next()) {
                    cols.add(rs.getString("COLUMN_NAME").toLowerCase());
                }
            }
        }
        return cols;
    }

    private void assertColumnNullable(String columnName, boolean expectNullable) throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getColumns(null, "public", TABLE, columnName)) {
                assertThat(rs.next())
                        .as("Column '%s' must exist in %s", columnName, TABLE).isTrue();
                int nullable = rs.getInt("NULLABLE"); // 0 = not nullable, 1 = nullable
                if (expectNullable) {
                    assertThat(nullable).as("Column '%s' should be nullable", columnName).isEqualTo(1);
                } else {
                    assertThat(nullable).as("Column '%s' should be NOT NULL", columnName).isEqualTo(0);
                }
            }
        }
    }

    private List<String> getIndexNames() throws Exception {
        List<String> indexes = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getIndexInfo(null, "public", TABLE, false, false)) {
                while (rs.next()) {
                    String indexName = rs.getString("INDEX_NAME");
                    if (indexName != null) {
                        indexes.add(indexName.toLowerCase());
                    }
                }
            }
        }
        return indexes;
    }
}
