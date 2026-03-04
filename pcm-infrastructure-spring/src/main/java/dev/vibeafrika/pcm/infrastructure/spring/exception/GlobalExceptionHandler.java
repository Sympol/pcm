package dev.vibeafrika.pcm.infrastructure.spring.exception;

import dev.vibeafrika.pcm.preference.domain.exception.*;
import dev.vibeafrika.pcm.profile.domain.exception.*;
import dev.vibeafrika.pcm.consent.domain.exception.*;
import dev.vibeafrika.pcm.segment.domain.exception.*;
import io.github.sympol.pure.asserts.AssertionException;
import io.github.sympol.pure.asserts.MissingMandatoryValueException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
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

    private static final String PROBLEM_BASE_URL = "https://api.pcm.vibeafrika.dev/problems";

    // ========== Preference Context Exceptions ==========

    @ExceptionHandler(PreferenceNotFoundException.class)
    public ProblemDetail handlePreferenceNotFound(PreferenceNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/preference-not-found"));
        problemDetail.setTitle("Preference Not Found");
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("preferenceId", ex.getPreferenceId().getValue());
        return problemDetail;
    }

    @ExceptionHandler(PreferenceDeletedException.class)
    public ProblemDetail handlePreferenceDeleted(PreferenceDeletedException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.GONE,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/preference-deleted"));
        problemDetail.setTitle("Preference Deleted");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(PreferenceValidationException.class)
    public ProblemDetail handlePreferenceValidation(PreferenceValidationException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/preference-validation-error"));
        problemDetail.setTitle("Preference Validation Error");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Profile Context Exceptions ==========

    @ExceptionHandler(ProfileNotFoundException.class)
    public ProblemDetail handleProfileNotFound(ProfileNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/profile-not-found"));
        problemDetail.setTitle("Profile Not Found");
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("profileId", ex.getProfileId().getValue());
        return problemDetail;
    }

    @ExceptionHandler(ProfileDeletedException.class)
    public ProblemDetail handleProfileDeleted(ProfileDeletedException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.GONE,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/profile-deleted"));
        problemDetail.setTitle("Profile Deleted");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(InvalidHandleException.class)
    public ProblemDetail handleInvalidHandle(InvalidHandleException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/invalid-handle"));
        problemDetail.setTitle("Invalid Handle");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Consent Context Exceptions ==========

    @ExceptionHandler(ConsentNotFoundException.class)
    public ProblemDetail handleConsentNotFound(ConsentNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/consent-not-found"));
        problemDetail.setTitle("Consent Not Found");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    @ExceptionHandler(ConsentRevokedException.class)
    public ProblemDetail handleConsentRevoked(ConsentRevokedException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.GONE,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/consent-revoked"));
        problemDetail.setTitle("Consent Revoked");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Segment Context Exceptions ==========

    @ExceptionHandler(SegmentNotFoundException.class)
    public ProblemDetail handleSegmentNotFound(SegmentNotFoundException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/segment-not-found"));
        problemDetail.setTitle("Segment Not Found");
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }

    // ========== Pure-Assert Validation Exceptions ==========

    /**
     * Handler for MissingMandatoryValueException (specific handler for better error messages).
     */
    @ExceptionHandler(MissingMandatoryValueException.class)
    public ProblemDetail handleMissingMandatoryValue(MissingMandatoryValueException ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/validation-error"));
        problemDetail.setTitle("Validation Error: Missing Mandatory Value");
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
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            ex.getMessage()
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/validation-error"));
        problemDetail.setTitle("Validation Error: " + ex.type().name());
        problemDetail.setProperty("timestamp", Instant.now());
        problemDetail.setProperty("field", ex.field());
        problemDetail.setProperty("errorType", ex.type().name());
        
        // Add all parameters from the exception
        if (ex.parameters() != null && !ex.parameters().isEmpty()) {
            ex.parameters().forEach(problemDetail::setProperty);
        }
        
        return problemDetail;
    }

    // ========== Generic Exception Handler ==========

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGenericException(Exception ex, WebRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "An unexpected error occurred"
        );
        problemDetail.setType(URI.create(PROBLEM_BASE_URL + "/internal-error"));
        problemDetail.setTitle("Internal Server Error");
        problemDetail.setProperty("timestamp", Instant.now());
        // Don't expose internal error details in production
        return problemDetail;
    }
}
