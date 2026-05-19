package dev.vibeafrika.pcm.profile.application.dto;

import java.util.List;
import java.util.UUID;
import java.util.Map;

/**
 * Response DTO for the data portability export.
 *
 * <p>Contains all personal data held by PCM for a given profile, in a
 * structured, machine-readable format. No framework annotations — pure data carrier.
 *
 * <p>The export intentionally omits internal technical fields (version, soft-delete
 * timestamps) that are not personal data and are not relevant to the data subject.
 */
public record ProfileDataExportResponse(

        /** Unique identifier of the exported profile. */
        UUID profileId,

        /** Tenant the profile belongs to. */
        String tenantId,

        /** Timestamp of the export generation (ISO-8601). */
        String exportedAt,

        /** Profile section — identity data. */
        ProfileSection profile,

        /** Consent section — full consent history. */
        List<ConsentExportEntry> consents,

        /** Preferences section — all stored preferences. */
        List<PreferenceExportEntry> preferences

) {
    public ProfileDataExportResponse {
        consents = consents != null ? List.copyOf(consents) : List.of();
        preferences = preferences != null ? List.copyOf(preferences) : List.of();
    }

    /**
     * Profile identity data included in the export.
     */
    public record ProfileSection(
            String handle, Map<String, Object> attributes,
            String createdAt,
            String updatedAt
    ) {
        public ProfileSection {
            attributes = attributes != null ? Map.copyOf(attributes) : Map.of();
        }
    }

    /**
     * A single consent record included in the export.
     * Includes the full event history for auditability.
     */
    public record ConsentExportEntry(
            UUID consentId,
            String purpose,
            String scope,
            String currentStatus,
            String createdAt,
            String updatedAt,
            List<ConsentEventEntry> history
    ) {
        public ConsentExportEntry {
            history = history != null ? List.copyOf(history) : List.of();
        }
    }

    /**
     * A single event in the consent history ledger.
     */
    public record ConsentEventEntry(
            String status,
            String timestamp
    ) {}

    /**
     * A single preference record included in the export.
     */
    public record PreferenceExportEntry(
            UUID preferenceId,
            Map<String, String> settings,
            String createdAt,
            String updatedAt
    ) {
        public PreferenceExportEntry {
            settings = settings != null ? Map.copyOf(settings) : Map.of();
        }
    }
}
