package dev.vibeafrika.pcm.preference.domain.exception;

import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;

/**
 * Thrown when a preference is not found.
 */
public class PreferenceNotFoundException extends PreferenceDomainException {
    private final PreferenceId preferenceId;

    public PreferenceNotFoundException(PreferenceId preferenceId) {
        super("Preference not found: " + preferenceId);
        this.preferenceId = preferenceId;
    }

    public PreferenceId getPreferenceId() {
        return preferenceId;
    }
}
