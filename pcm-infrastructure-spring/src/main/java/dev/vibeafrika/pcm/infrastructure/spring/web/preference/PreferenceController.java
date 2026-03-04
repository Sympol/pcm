package dev.vibeafrika.pcm.infrastructure.spring.web.preference;

import dev.vibeafrika.pcm.preference.application.dto.*;
import dev.vibeafrika.pcm.preference.application.usecase.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for Preference operations.
 * Part of the unified Spring Boot infrastructure serving all bounded contexts.
 * Delegates to use cases in the preference-application layer.
 */
@RestController
@RequestMapping("/api/v1/preferences")
public class PreferenceController {

    private final CreatePreferenceUseCase createPreferenceUseCase;
    private final UpdatePreferenceUseCase updatePreferenceUseCase;
    private final GetPreferenceUseCase getPreferenceUseCase;
    private final DeletePreferenceUseCase deletePreferenceUseCase;

    public PreferenceController(
            CreatePreferenceUseCase createPreferenceUseCase,
            UpdatePreferenceUseCase updatePreferenceUseCase,
            GetPreferenceUseCase getPreferenceUseCase,
            DeletePreferenceUseCase deletePreferenceUseCase) {
        this.createPreferenceUseCase = createPreferenceUseCase;
        this.updatePreferenceUseCase = updatePreferenceUseCase;
        this.getPreferenceUseCase = getPreferenceUseCase;
        this.deletePreferenceUseCase = deletePreferenceUseCase;
    }

    /**
     * Create a new preference.
     * POST /api/v1/preferences
     */
    @PostMapping
    public ResponseEntity<PreferenceResponse> createPreference(
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody CreatePreferenceRequest request) {
        
        // Add tenant ID to request
        CreatePreferenceRequest requestWithTenant = new CreatePreferenceRequest(
            tenantId,
            request.profileId(),
            request.settings()
        );
        
        PreferenceResponse response = createPreferenceUseCase.execute(requestWithTenant);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Update preference settings.
     * PUT /api/v1/preferences/{id}
     */
    @PutMapping("/{id}")
    public ResponseEntity<PreferenceResponse> updatePreference(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody UpdatePreferenceRequest request) {
        
        UpdatePreferenceRequest requestWithIdAndTenant = new UpdatePreferenceRequest(
            id,
            tenantId,
            request.settings()
        );
        
        PreferenceResponse response = updatePreferenceUseCase.execute(requestWithIdAndTenant);
        return ResponseEntity.ok(response);
    }

    /**
     * Get preference by ID.
     * GET /api/v1/preferences/{id}
     */
    @GetMapping("/{id}")
    public ResponseEntity<PreferenceResponse> getPreference(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        GetPreferenceRequest request = new GetPreferenceRequest(id, tenantId);
        PreferenceResponse response = getPreferenceUseCase.execute(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Delete preference (soft delete).
     * DELETE /api/v1/preferences/{id}
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePreference(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        DeletePreferenceRequest request = new DeletePreferenceRequest(id, tenantId);
        deletePreferenceUseCase.execute(request);
        return ResponseEntity.noContent().build();
    }
}
