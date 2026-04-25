package dev.vibeafrika.pcm.infrastructure.spring.exception;

import dev.vibeafrika.pcm.preference.domain.exception.*;
import dev.vibeafrika.pcm.profile.domain.exception.*;
import dev.vibeafrika.pcm.consent.domain.exception.*;
import dev.vibeafrika.pcm.segment.domain.exception.*;
import io.github.sympol.pure.asserts.AssertionException;
import io.github.sympol.pure.asserts.MissingMandatoryValueException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.net.URI;
import java.time.Instant;

/**
 * Global exception handler for all bounded contexts.
 * Implements RFC 7807 Problem Details for HTTP APIs.
 * Translates domain exceptions and pure-assert typed exceptions to HTTP responses.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String PROBLEM_BASE_URL = "http://localhost/problems";

    // ========== Preference Context Exceptions ==========

    @ExceptionHandler(PreferenceNotFoundException.class)
    public ProblemDetail handlePreferenceNotFound(PreferenceNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/preference-not-found"));
        problemDetail.setTitle("Preference Not Found");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("preferenceId", ex.getPreferenceId().getValue());
        return problemDetail;
    }

    @ExceptionHandler(PreferenceDeletedException.class)
    public ProblemDetail handlePreferenceDeleted(PreferenceDeletedException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.GONE, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/preference-deleted"));
        problemDetail.setTitle("Preference Deleted");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(PreferenceValidationException.class)
    public ProblemDetail handlePreferenceValidation(PreferenceValidationException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/preference-validation-error"));
        problemDetail.setTitle("Preference Validation Error");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Profile Context Exceptions ==========

    @ExceptionHandler(ProfileNotFoundException.class)
    public ProblemDetail handleProfileNotFound(ProfileNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/profile-not-found"));
        problemDetail.setTitle("Profile Not Found");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("profileId", ex.getProfileId().getValue());
        return problemDetail;
    }

    @ExceptionHandler(ProfileDeletedException.class)
    public ProblemDetail handleProfileDeleted(ProfileDeletedException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.GONE, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/profile-deleted"));
        problemDetail.setTitle("Profile Deleted");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(InvalidHandleException.class)
    public ProblemDetail handleInvalidHandle(InvalidHandleException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/invalid-handle"));
        problemDetail.setTitle("Invalid Handle");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Consent Context Exceptions ==========

    @ExceptionHandler(ConsentNotFoundException.class)
    public ProblemDetail handleConsentNotFound(ConsentNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/consent-not-found"));
        problemDetail.setTitle("Consent Not Found");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(ConsentRevokedException.class)
    public ProblemDetail handleConsentRevoked(ConsentRevokedException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/consent-revoked"));
        problemDetail.setTitle("Consent Already Revoked");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(InvalidConsentPurposeException.class)
    public ProblemDetail handleInvalidConsentPurpose(InvalidConsentPurposeException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/invalid-consent-purpose"));
        problemDetail.setTitle("Invalid Consent Purpose");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Segment Context Exceptions ==========

    @ExceptionHandler(SegmentNotFoundException.class)
    public ProblemDetail handleSegmentNotFound(SegmentNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/segment-not-found"));
        problemDetail.setTitle("Segment Not Found");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        if (ex.getSegmentId() != null) {
            problemDetail.setProperty("segmentId", ex.getSegmentId().getValue());
        }
        return problemDetail;
    }

    @ExceptionHandler(SegmentValidationException.class)
    public ProblemDetail handleSegmentValidation(SegmentValidationException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/segment-validation-error"));
        problemDetail.setTitle("Segment Validation Error");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(InvalidSegmentCriteriaException.class)
    public ProblemDetail handleInvalidSegmentCriteria(InvalidSegmentCriteriaException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/invalid-segment-criteria"));
        problemDetail.setTitle("Invalid Segment Criteria");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Generic Validation Exceptions ==========

    /**
     * Handler for IllegalArgumentException - typically thrown by DTO compact constructors
     * for missing required fields (e.g., blank handle, null profile ID).
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/validation-error"));
        problemDetail.setTitle("Validation Error: Invalid Argument");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Pure-Assert Validation Exceptions ==========

    /**
     * Handler for MissingMandatoryValueException (specific handler for better error messages).
     */
    @ExceptionHandler(MissingMandatoryValueException.class)
    public ProblemDetail handleMissingMandatoryValue(MissingMandatoryValueException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/validation-error"));
        problemDetail.setTitle("Validation Error: Missing Mandatory Value");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("field", ex.field());
        problemDetail.setProperty("errorType", ex.type().name());
        return problemDetail;
    }

    /**
     * Generic handler for all pure-assert validation exceptions.
     * Catches StringTooShortException, StringTooLongException, InvalidPatternException, etc.
     */
    @ExceptionHandler(AssertionException.class)
    public ProblemDetail handleAssertionException(AssertionException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/validation-error"));
        problemDetail.setTitle("Validation Error: " + ex.type().name());
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("field", ex.field());
        problemDetail.setProperty("errorType", ex.type().name());

        // Add all parameters from the exception
        if (ex.parameters() != null && !ex.parameters().isEmpty()) {
            ex.parameters().forEach(problemDetail::setProperty);
        }

        return problemDetail;
    }

    // ========== Spring MVC Exceptions ==========

    /**
     * Handler for missing required request headers (e.g., X-Tenant-Id).
     * Returns 400 BAD_REQUEST instead of 500.
     */
    @ExceptionHandler(MissingRequestHeaderException.class)
    public ProblemDetail handleMissingRequestHeader(MissingRequestHeaderException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST, "Required header '" + ex.getHeaderName() + "' is missing");
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/missing-header"));
        problemDetail.setTitle("Missing Required Header");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("headerName", ex.getHeaderName());
        return problemDetail;
    }

    /**
     * Handler for unreadable HTTP message bodies (e.g., JSON parse errors from DTO validation).
     * Returns 400 BAD_REQUEST instead of 500.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail handleHttpMessageNotReadable(HttpMessageNotReadableException ex, WebRequest request) {
        String detail = ex.getMessage() != null ? ex.getMessage() : "Request body is not readable";
        // Extract the root cause message if it's an IllegalArgumentException from DTO validation
        Throwable cause = ex.getCause();
        if (cause != null && cause.getMessage() != null) {
            detail = cause.getMessage();
        }
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, detail);
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/invalid-request-body"));
        problemDetail.setTitle("Invalid Request Body");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Generic Exception Handler ==========

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGenericException(Exception ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/internal-error"));
        problemDetail.setTitle("Internal Server Error");
        problemDetail.setInstance(requestUri(request));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Helper ==========

    private URI requestUri(WebRequest request) {
        return URI.create(request.getDescription(false).replace("uri=", ""));
    }
}
