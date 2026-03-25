package dev.vibeafrika.pcm.infrastructure.spring.profile;

import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.repository.SpringDataProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the Profile JPA repository.
 *
 * Uses @DataJpaTest with Testcontainers PostgreSQL to verify database persistence.
 * Tests cover save, findById, findByHandle, existsByHandle, and soft delete.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class ProfileRepositoryIntegrationTest {

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
        registry.add("spring.flyway.enabled", () -> "false");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    }

    @Autowired
    private SpringDataProfileRepository repository;

    @Autowired
    private TestEntityManager entityManager;

    private static final String TENANT_ID = "tenant-repo-test";

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    // -------------------------------------------------------------------------
    // 1. Save and findById
    // -------------------------------------------------------------------------

    @Test
    void save_persistsProfileAndReturnsWithId() {
        ProfileJpaEntity entity = buildEntity("testhandle", TENANT_ID);

        ProfileJpaEntity saved = repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findById(saved.getId());

        assertThat(found).isPresent();
        assertThat(found.get().getHandle()).isEqualTo("testhandle");
        assertThat(found.get().getTenantId()).isEqualTo(TENANT_ID);
        assertThat(found.get().getId()).isEqualTo(saved.getId());
    }

    @Test
    void save_persistsAttributes() {
        ProfileJpaEntity entity = buildEntity("attrhandle", TENANT_ID);
        entity.setAttributes(Map.of("email", "user@example.com", "age", "30"));

        ProfileJpaEntity saved = repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findById(saved.getId());

        assertThat(found).isPresent();
        assertThat(found.get().getAttributes()).containsEntry("email", "user@example.com");
        assertThat(found.get().getAttributes()).containsEntry("age", "30");
    }

    @Test
    void findById_returnsEmpty_whenNotFound() {
        Optional<ProfileJpaEntity> found = repository.findById(UUID.randomUUID());

        assertThat(found).isEmpty();
    }

    // -------------------------------------------------------------------------
    // 2. findByHandleAndTenantId
    // -------------------------------------------------------------------------

    @Test
    void findByHandleAndTenantId_returnsProfile_whenExists() {
        ProfileJpaEntity entity = buildEntity("findbyhandle", TENANT_ID);
        repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findByHandleAndTenantId("findbyhandle", TENANT_ID);

        assertThat(found).isPresent();
        assertThat(found.get().getHandle()).isEqualTo("findbyhandle");
        assertThat(found.get().getTenantId()).isEqualTo(TENANT_ID);
    }

    @Test
    void findByHandleAndTenantId_returnsEmpty_whenHandleDoesNotMatch() {
        ProfileJpaEntity entity = buildEntity("existinghandle", TENANT_ID);
        repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findByHandleAndTenantId("nonexistent", TENANT_ID);

        assertThat(found).isEmpty();
    }

    @Test
    void findByHandleAndTenantId_returnsEmpty_whenTenantDoesNotMatch() {
        ProfileJpaEntity entity = buildEntity("crosstenanthandle", TENANT_ID);
        repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findByHandleAndTenantId("crosstenanthandle", "other-tenant");

        assertThat(found).isEmpty();
    }

    // -------------------------------------------------------------------------
    // 3. existsByHandleAndTenantId
    // -------------------------------------------------------------------------

    @Test
    void existsByHandleAndTenantId_returnsTrue_whenExists() {
        ProfileJpaEntity entity = buildEntity("existshandle", TENANT_ID);
        repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        boolean exists = repository.existsByHandleAndTenantId("existshandle", TENANT_ID);

        assertThat(exists).isTrue();
    }

    @Test
    void existsByHandleAndTenantId_returnsFalse_whenNotExists() {
        boolean exists = repository.existsByHandleAndTenantId("ghosthandle", TENANT_ID);

        assertThat(exists).isFalse();
    }

    // -------------------------------------------------------------------------
    // 4. Soft delete (deleted flag)
    // -------------------------------------------------------------------------

    @Test
    void save_withDeletedFlag_persistsDeletedState() {
        ProfileJpaEntity entity = buildEntity("deletedhandle", TENANT_ID);
        entity.setDeleted(true);

        ProfileJpaEntity saved = repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findById(saved.getId());

        assertThat(found).isPresent();
        assertThat(found.get().isDeleted()).isTrue();
    }

    @Test
    void update_deletedFlag_persistsChange() {
        ProfileJpaEntity entity = buildEntity("softdeletehandle", TENANT_ID);
        ProfileJpaEntity saved = repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        // Mark as deleted
        ProfileJpaEntity toUpdate = repository.findById(saved.getId()).orElseThrow();
        toUpdate.setDeleted(true);
        repository.save(toUpdate);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findById(saved.getId());

        assertThat(found).isPresent();
        assertThat(found.get().isDeleted()).isTrue();
    }

    // -------------------------------------------------------------------------
    // 5. findByIdAndTenantId
    // -------------------------------------------------------------------------

    @Test
    void findByIdAndTenantId_returnsProfile_whenBothMatch() {
        ProfileJpaEntity entity = buildEntity("idtenanthandle", TENANT_ID);
        ProfileJpaEntity saved = repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findByIdAndTenantId(saved.getId(), TENANT_ID);

        assertThat(found).isPresent();
        assertThat(found.get().getId()).isEqualTo(saved.getId());
    }

    @Test
    void findByIdAndTenantId_returnsEmpty_whenTenantDoesNotMatch() {
        ProfileJpaEntity entity = buildEntity("wrongtenanthandle", TENANT_ID);
        ProfileJpaEntity saved = repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findByIdAndTenantId(saved.getId(), "wrong-tenant");

        assertThat(found).isEmpty();
    }

    // -------------------------------------------------------------------------
    // 6. Audit fields populated
    // -------------------------------------------------------------------------

    @Test
    void save_populatesAuditFields() {
        ProfileJpaEntity entity = buildEntity("audithandle", TENANT_ID);

        ProfileJpaEntity saved = repository.save(entity);
        entityManager.flush();
        entityManager.clear();

        Optional<ProfileJpaEntity> found = repository.findById(saved.getId());

        assertThat(found).isPresent();
        assertThat(found.get().getCreatedAt()).isNotNull();
        assertThat(found.get().getUpdatedAt()).isNotNull();
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private ProfileJpaEntity buildEntity(String handle, String tenantId) {
        ProfileJpaEntity entity = new ProfileJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setHandle(handle);
        entity.setTenantId(tenantId);
        entity.setAttributes(Map.of());
        entity.setDeleted(false);
        return entity;
    }
}
