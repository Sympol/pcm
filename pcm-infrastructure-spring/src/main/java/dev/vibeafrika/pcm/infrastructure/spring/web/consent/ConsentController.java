package dev.vibeafrika.pcm.infrastructure.spring.web.consent;

import dev.vibeafrika.pcm.consent.application.dto.*;
import dev.vibeafrika.pcm.consent.application.usecase.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/consents")
public class ConsentController {

    private final GrantConsentUseCase grantConsentUseCase;
    private final RevokeConsentUseCase revokeConsentUseCase;

    public ConsentController(
            GrantConsentUseCase grantConsentUseCase,
            RevokeConsentUseCase revokeConsentUseCase) {
        this.grantConsentUseCase = grantConsentUseCase;
        this.revokeConsentUseCase = revokeConsentUseCase;
    }

    @PostMapping
    public ResponseEntity<ConsentResponse> grantConsent(
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody GrantConsentRequest request) {
        
        GrantConsentRequest requestWithTenant = new GrantConsentRequest(
            request.profileId(),
            tenantId,
            request.purpose(),
            request.scope()
        );
        
        ConsentResponse response = grantConsentUseCase.execute(requestWithTenant);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ConsentResponse> revokeConsent(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        RevokeConsentRequest request = new RevokeConsentRequest(id, tenantId);
        ConsentResponse response = revokeConsentUseCase.execute(request);
        return ResponseEntity.ok(response);
    }
}
