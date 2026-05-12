package dev.vibeafrika.pcm.infrastructure.spring.web.consent;

import dev.vibeafrika.pcm.consent.application.dto.*;
import dev.vibeafrika.pcm.consent.application.usecase.*;
import dev.vibeafrika.pcm.consent.domain.model.ConsentId;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/consents")
public class ConsentController {

    private final GrantConsentUseCase grantConsentUseCase;
    private final RevokeConsentUseCase revokeConsentUseCase;
    private final VerifyConsentUseCase verifyConsentUseCase;
    private final GetConsentHistoryUseCase getConsentHistoryUseCase;

    public ConsentController(
            GrantConsentUseCase grantConsentUseCase,
            RevokeConsentUseCase revokeConsentUseCase,
            VerifyConsentUseCase verifyConsentUseCase,
            GetConsentHistoryUseCase getConsentHistoryUseCase) {
        this.grantConsentUseCase = grantConsentUseCase;
        this.revokeConsentUseCase = revokeConsentUseCase;
        this.verifyConsentUseCase = verifyConsentUseCase;
        this.getConsentHistoryUseCase = getConsentHistoryUseCase;
    }

    /**
     * POST /api/v1/consents - Grant consent.
     */
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

    /**
     * DELETE /api/v1/consents/{id} - Revoke consent.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<ConsentResponse> revokeConsent(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        RevokeConsentRequest request = new RevokeConsentRequest(id, tenantId);
        ConsentResponse response = revokeConsentUseCase.execute(request);
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/v1/consents/verify?consentId={id} - Verify consent is active.
     */
    @GetMapping("/verify")
    public ResponseEntity<Boolean> verifyConsent(@RequestParam UUID consentId) {
        boolean active = verifyConsentUseCase.execute(ConsentId.of(consentId));
        return ResponseEntity.ok(active);
    }

    /**
     * GET /api/v1/consents/history?consentId={id} - Get consent event history.
     */
    @GetMapping("/history")
    public ResponseEntity<ConsentHistoryResponse> getConsentHistory(@RequestParam UUID consentId) {
        ConsentHistoryResponse response = getConsentHistoryUseCase.execute(ConsentId.of(consentId));
        return ResponseEntity.ok(response);
    }

}
