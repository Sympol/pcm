package dev.vibeafrika.pcm.infrastructure.encryption.repository;

import dev.vibeafrika.pcm.infrastructure.encryption.entity.AuditLogEntryEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;

/**
 * Append-only Spring Data JPA repository for audit log entries.
 *
 * <p>This interface intentionally exposes only read and append operations.
 * The inherited {@code deleteById}, {@code delete}, {@code deleteAll}, and
 * {@code deleteAllById} methods from {@link JpaRepository} are overridden to
 * throw {@link UnsupportedOperationException}, enforcing the append-only
 * guarantee required by Requirement 7.9.
 *
 * <p>Callers must use {@link #save(Object)} to append new entries and the
 * {@code find*} methods to query them.
 */
@Repository
public interface AuditLogEntryRepository extends JpaRepository<AuditLogEntryEntity, Long> {

    /**
     * Returns a page of entries whose {@code createdAt} falls within the
     * given range, ordered by {@code createdAt} ascending.
     */
    Page<AuditLogEntryEntity> findByCreatedAtBetweenOrderByCreatedAtAsc(
            Instant from, Instant to, Pageable pageable);

    /**
     * Returns a page of entries for a specific event type.
     */
    Page<AuditLogEntryEntity> findByEventTypeOrderByCreatedAtAsc(
            String eventType, Pageable pageable);

    // -------------------------------------------------------------------------
    // Append-only enforcement – delete operations are prohibited
    // -------------------------------------------------------------------------

    @Override
    default void deleteById(Long id) {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }

    @Override
    default void delete(AuditLogEntryEntity entity) {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }

    @Override
    default void deleteAll() {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }

    @Override
    default void deleteAll(Iterable<? extends AuditLogEntryEntity> entities) {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }

    @Override
    default void deleteAllById(Iterable<? extends Long> ids) {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }

    @Override
    default void deleteAllInBatch() {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }

    @Override
    default void deleteAllInBatch(Iterable<AuditLogEntryEntity> entities) {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }

    @Override
    default void deleteAllByIdInBatch(Iterable<Long> ids) {
        throw new UnsupportedOperationException(
                "Audit log entries are append-only and cannot be deleted");
    }
}
