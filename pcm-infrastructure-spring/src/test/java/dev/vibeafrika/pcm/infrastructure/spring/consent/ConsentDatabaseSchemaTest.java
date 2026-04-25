package dev.vibeafrika.pcm.infrastructure.spring.consent;

import org.junit.jupiter.api.DisplayName;
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
 * Database schema validation for the Consent context.
 *
 * Verifies that Flyway-applied schema for consent tables matches the expected
 * structure: correct table names (with consent_ prefix), required columns,
 * NOT NULL constraints, and indexes.
 */
@DisplayName("Consent Database Schema Validation")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ConsentDatabaseSchemaTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_consent_schema_test")
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

    private static final String CONSENTS_TABLE = "consent_consents";
    private static final String EVENTS_TABLE = "consent_events";

    // -------------------------------------------------------------------------
    // 1. Flyway migration validation
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Flyway V1 migration is present and successful")
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
    // 2. Table existence with correct prefix
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("consent_consents table exists with correct prefix")
    void consentConsentsTable_exists() throws Exception {
        assertThat(tableExists(CONSENTS_TABLE))
            .as("Table 'consent_consents' must exist with 'consent_' prefix")
            .isTrue();
    }

    @Test
    @DisplayName("consent_events table exists with correct prefix")
    void consentEventsTable_exists() throws Exception {
        assertThat(tableExists(EVENTS_TABLE))
            .as("Table 'consent_events' must exist with 'consent_' prefix")
            .isTrue();
    }

    @Test
    @DisplayName("No 'consents' table without prefix exists")
    void noUnprefixedConsentsTable() throws Exception {
        assertThat(tableExists("consents"))
            .as("Table 'consents' without prefix must NOT exist; use 'consent_consents'")
            .isFalse();
    }

    // -------------------------------------------------------------------------
    // 3. Required columns in consent_consents
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("consent_consents has all required columns")
    void consentConsentsTable_hasRequiredColumns() throws Exception {
        List<String> columns = getColumns(CONSENTS_TABLE);

        assertThat(columns)
            .as("consent_consents must contain required columns")
            .contains("id", "profile_id", "tenant_id", "purpose", "scope",
                      "status", "created_at", "updated_at", "version");
    }

    // -------------------------------------------------------------------------
    // 4. NOT NULL constraints on key columns
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("id column is non-nullable")
    void idColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "id", false);
    }

    @Test
    @DisplayName("profile_id column is non-nullable")
    void profileIdColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "profile_id", false);
    }

    @Test
    @DisplayName("tenant_id column is non-nullable")
    void tenantIdColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "tenant_id", false);
    }

    @Test
    @DisplayName("purpose column is non-nullable")
    void purposeColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "purpose", false);
    }

    @Test
    @DisplayName("scope column is non-nullable")
    void scopeColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "scope", false);
    }

    @Test
    @DisplayName("status column is non-nullable")
    void statusColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "status", false);
    }

    @Test
    @DisplayName("created_at column is non-nullable")
    void createdAtColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "created_at", false);
    }

    @Test
    @DisplayName("updated_at column is non-nullable")
    void updatedAtColumn_isNonNullable() throws Exception {
        assertColumnNullable(CONSENTS_TABLE, "updated_at", false);
    }

    // -------------------------------------------------------------------------
    // 5. Primary key
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("id is the primary key of consent_consents")
    void idColumn_isPrimaryKey() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getPrimaryKeys(null, null, CONSENTS_TABLE)) {
                assertThat(rs.next())
                    .as("consent_consents must have a primary key").isTrue();
                assertThat(rs.getString("COLUMN_NAME"))
                    .as("Primary key must be the 'id' column").isEqualTo("id");
            }
        }
    }

    // -------------------------------------------------------------------------
    // 6. Indexes
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("consent_consents has required indexes")
    void consentConsentsTable_hasRequiredIndexes() throws Exception {
        List<String> indexes = getIndexNames(CONSENTS_TABLE);

        assertThat(indexes)
            .as("consent_consents must have profile index")
            .anySatisfy(idx -> assertThat(idx).contains("consent_profile"));

        assertThat(indexes)
            .as("consent_consents must have tenant index")
            .anySatisfy(idx -> assertThat(idx).contains("consent_tenant"));
    }

    // -------------------------------------------------------------------------
    // 7. consent_events ledger table
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("consent_events has required columns for ledger pattern")
    void consentEventsTable_hasRequiredColumns() throws Exception {
        List<String> columns = getColumns(EVENTS_TABLE);

        assertThat(columns)
            .as("consent_events must contain ledger columns")
            .contains("id", "consent_id", "status", "timestamp");
    }

    @Test
    @DisplayName("consent_events.consent_id is non-nullable")
    void consentEventsConsentId_isNonNullable() throws Exception {
        assertColumnNullable(EVENTS_TABLE, "consent_id", false);
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
        List<String> cols = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getColumns(null, null, tableName, "%")) {
                while (rs.next()) {
                    cols.add(rs.getString("COLUMN_NAME").toLowerCase());
                }
            }
        }
        return cols;
    }

    private void assertColumnNullable(String table, String column, boolean expectNullable) throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getColumns(null, null, table, column)) {
                assertThat(rs.next())
                    .as("Column '%s' must exist in %s", column, table).isTrue();
                int nullable = rs.getInt("NULLABLE");
                if (expectNullable) {
                    assertThat(nullable).as("Column '%s' should be nullable", column).isEqualTo(1);
                } else {
                    assertThat(nullable).as("Column '%s' should be NOT NULL", column).isEqualTo(0);
                }
            }
        }
    }

    private List<String> getIndexNames(String tableName) throws Exception {
        List<String> indexes = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getIndexInfo(null, null, tableName, false, false)) {
                while (rs.next()) {
                    String name = rs.getString("INDEX_NAME");
                    if (name != null) indexes.add(name.toLowerCase());
                }
            }
        }
        return indexes;
    }
}
