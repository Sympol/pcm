package dev.vibeafrika.pcm.infrastructure.spring.web;

import dev.vibeafrika.pcm.segment.application.dto.*;
import dev.vibeafrika.pcm.segment.application.usecase.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST controller for Segment context.
 * Handles HTTP requests and delegates to use cases.
 */
@RestController
@RequestMapping("/api/v1/segments")
public class SegmentController {

    private final CreateSegmentUseCase createSegmentUseCase;
    private final UpdateSegmentUseCase updateSegmentUseCase;
    private final GetSegmentUseCase getSegmentUseCase;
    private final DeleteSegmentUseCase deleteSegmentUseCase;
    private final EvaluateSegmentUseCase evaluateSegmentUseCase;

    public SegmentController(
            CreateSegmentUseCase createSegmentUseCase,
            UpdateSegmentUseCase updateSegmentUseCase,
            GetSegmentUseCase getSegmentUseCase,
            DeleteSegmentUseCase deleteSegmentUseCase,
            EvaluateSegmentUseCase evaluateSegmentUseCase) {
        this.createSegmentUseCase = createSegmentUseCase;
        this.updateSegmentUseCase = updateSegmentUseCase;
        this.getSegmentUseCase = getSegmentUseCase;
        this.deleteSegmentUseCase = deleteSegmentUseCase;
        this.evaluateSegmentUseCase = evaluateSegmentUseCase;
    }

    @PostMapping
    public ResponseEntity<SegmentResponse> createSegment(
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody CreateSegmentRequest request) {
        
        CreateSegmentRequest requestWithTenant = new CreateSegmentRequest(
            tenantId,
            request.profileId(),
            request.tags(),
            request.scores()
        );
        
        SegmentResponse response = createSegmentUseCase.execute(requestWithTenant);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/{id}")
    public ResponseEntity<SegmentResponse> updateSegment(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody UpdateSegmentRequest request) {
        
        UpdateSegmentRequest requestWithId = new UpdateSegmentRequest(
            id,
            request.tags(),
            request.scores()
        );
        
        SegmentResponse response = updateSegmentUseCase.execute(requestWithId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<SegmentResponse> getSegment(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        
        GetSegmentRequest request = new GetSegmentRequest(id);
        SegmentResponse response = getSegmentUseCase.execute(request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteSegment(
            @PathVariable UUID id,
            @RequestHeader("X-Tenant-Id") String tenantId) {
        
        DeleteSegmentRequest request = new DeleteSegmentRequest(id);
        deleteSegmentUseCase.execute(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/evaluate")
    public ResponseEntity<List<SegmentResponse>> evaluateSegments(
            @RequestHeader("X-Tenant-Id") String tenantId,
            @RequestBody EvaluateSegmentRequest request) {
        
        EvaluateSegmentRequest requestWithTenant = new EvaluateSegmentRequest(
            request.profileId(),
            tenantId
        );
        
        List<SegmentResponse> response = evaluateSegmentUseCase.execute(requestWithTenant);
        return ResponseEntity.ok(response);
    }
}
