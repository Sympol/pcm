package dev.vibeafrika.pcm.infrastructure.spring.web.profile;

import dev.vibeafrika.pcm.profile.application.dto.*;
import dev.vibeafrika.pcm.profile.application.usecase.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for Profile operations.
 * Part of the unified Spring Boot infrastructure.
 */
@RestController
@RequestMapping("/api/v1/profiles")
public class ProfileController {

    private final CreateProfileUseCase createProfileUseCase;
    private final UpdateProfileUseCase updateProfileUseCase;
    private final GetProfileUseCase getProfileUseCase;
    private final EraseProfileUseCase eraseProfileUseCase;

    public ProfileController(
            CreateProfileUseCase createProfileUseCase,
            UpdateProfileUseCase updateProfileUseCase,
            GetProfileUseCase getProfileUseCase,
            EraseProfileUseCase eraseProfileUseCase) {
        this.createProfileUseCase = createProfileUseCase;
        this.updateProfileUseCase = updateProfileUseCase;
        this.getProfileUseCase = getProfileUseCase;
        this.eraseProfileUseCase = eraseProfileUseCase;
    }

    @PostMapping
    public ResponseEntity<ProfileResponse> createProfile(
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody CreateProfileRequest request) {
        
        CreateProfileRequest requestWithTenant = new CreateProfileRequest(
            tenantId,
            request.handle(),
            request.attributes()
        );
        
        ProfileResponse response = createProfileUseCase.execute(requestWithTenant);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/{id}")
    public ResponseEntity<ProfileResponse> updateProfile(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody UpdateProfileRequest request) {
        
        UpdateProfileRequest requestWithIds = new UpdateProfileRequest(
            id,
            tenantId,
            request.attributes()
        );
        
        ProfileResponse response = updateProfileUseCase.execute(requestWithIds);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ProfileResponse> getProfile(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        
        GetProfileRequest request = new GetProfileRequest(id, tenantId);
        ProfileResponse response = getProfileUseCase.execute(request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ProfileResponse> eraseProfile(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        
        EraseProfileRequest request = new EraseProfileRequest(id, tenantId);
        ProfileResponse response = eraseProfileUseCase.execute(request);
        return ResponseEntity.ok(response);
    }
}
