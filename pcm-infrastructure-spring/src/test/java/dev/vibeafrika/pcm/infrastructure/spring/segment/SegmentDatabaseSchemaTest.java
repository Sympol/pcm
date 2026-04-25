package dev.vibeafrika.pcm.infrastructure.spring.segment;

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
 * Database schema validation for the Segment context.
 *
 * Verifies that Flyway-applied schema for segment tables matches the expected
 * structure: correct table names (with segment_ prefix), required columns,
 * NOT NULL constraints, and indexes.
 */
@DisplayName("Segment Database Schema Validation")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class SegmentDatabaseSchemaTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("pcm_segment_schema_test")
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

    private static final String SEGMENTS_TABLE = "segment_segments";
    private static final String TAGS_TABLE = "segment_tags";

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
    @DisplayName("segment_segments table exists with correct prefix")
    void segmentSegmentsTable_exists() throws Exception {
        assertThat(tableExists(SEGMENTS_TABLE))
            .as("Table 'segment_segments' must exist with 'segment_' prefix")
            .isTrue();
    }

    @Test
    @DisplayName("segment_tags table exists with correct prefix")
    void segmentTagsTable_exists() throws Exception {
        assertThat(tableExists(TAGS_TABLE))
            .as("Table 'segment_tags' must exist with 'segment_' prefix")
            .isTrue();
    }

    @Test
    @DisplayName("No 'segments' table without prefix exists")
    void noUnprefixedSegmentsTable() throws Exception {
        assertThat(tableExists("segments"))
            .as("Table 'segments' without prefix must NOT exist; use 'segment_segments'")
            .isFalse();
    }

    // -------------------------------------------------------------------------
    // 3. Required columns in segment_segments
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("segment_segments has all required columns")
    void segmentSegmentsTable_hasRequiredColumns() throws Exception {
        List<String> columns = getColumns(SEGMENTS_TABLE);

        assertThat(columns)
            .as("segment_segments must contain required columns")
            .contains("id", "tenant_id", "profile_id", "scores",
                      "last_updated", "created_at", "updated_at");
    }

    // -------------------------------------------------------------------------
    // 4. NOT NULL constraints on key columns
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("id column is non-nullable")
    void idColumn_isNonNullable() throws Exception {
        assertColumnNullable(SEGMENTS_TABLE, "id", false);
    }

    @Test
    @DisplayName("tenant_id column is non-nullable")
    void tenantIdColumn_isNonNullable() throws Exception {
        assertColumnNullable(SEGMENTS_TABLE, "tenant_id", false);
    }

    @Test
    @DisplayName("profile_id column is non-nullable")
    void profileIdColumn_isNonNullable() throws Exception {
        assertColumnNullable(SEGMENTS_TABLE, "profile_id", false);
    }

    @Test
    @DisplayName("last_updated column is non-nullable")
    void lastUpdatedColumn_isNonNullable() throws Exception {
        assertColumnNullable(SEGMENTS_TABLE, "last_updated", false);
    }

    @Test
    @DisplayName("created_at column is non-nullable")
    void createdAtColumn_isNonNullable() throws Exception {
        assertColumnNullable(SEGMENTS_TABLE, "created_at", false);
    }

    @Test
    @DisplayName("updated_at column is non-nullable")
    void updatedAtColumn_isNonNullable() throws Exception {
        assertColumnNullable(SEGMENTS_TABLE, "updated_at", false);
    }

    // -------------------------------------------------------------------------
    // 5. Primary key
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("id is the primary key of segment_segments")
    void idColumn_isPrimaryKey() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getPrimaryKeys(null, null, SEGMENTS_TABLE)) {
                assertThat(rs.next())
                    .as("segment_segments must have a primary key").isTrue();
                assertThat(rs.getString("COLUMN_NAME"))
                    .as("Primary key must be the 'id' column").isEqualTo("id");
            }
        }
    }

    // -------------------------------------------------------------------------
    // 6. Indexes
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("segment_segments has tenant and profile indexes")
    void segmentSegmentsTable_hasRequiredIndexes() throws Exception {
        List<String> indexes = getIndexNames(SEGMENTS_TABLE);

        assertThat(indexes)
            .as("segment_segments must have tenant index")
            .anySatisfy(idx -> assertThat(idx).contains("segment_tenant"));

        assertThat(indexes)
            .as("segment_segments must have profile index")
            .anySatisfy(idx -> assertThat(idx).contains("segment_profile"));
    }

    // -------------------------------------------------------------------------
    // 7. segment_tags join table
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("segment_tags has segment_id and tag columns")
    void segmentTagsTable_hasRequiredColumns() throws Exception {
        List<String> columns = getColumns(TAGS_TABLE);

        assertThat(columns)
            .as("segment_tags must contain segment_id and tag columns")
            .contains("segment_id", "tag");
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
