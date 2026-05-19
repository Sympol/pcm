package dev.vibeafrika.pcm.common.asserts;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Map;
import java.util.function.Predicate;

public final class Validation {

    private Validation() {
        throw new AssertionError("Cette classe ne peut pas être instanciée.");
    }

    // --- Validation de nullité ---
    public static <T> T requireNonNull(T value, String valueName) {
        if (value == null) {
            throw RequiredValueException.forNullValue(valueName);
        }
        return value;
    }

    // --- Validation de chaîne non vide ---
    public static String requireNonEmpty(String value, String valueName) {
        if (value == null || value.trim().isEmpty()) {
            throw RequiredValueException.forEmptyValue(valueName);
        }
        return value;
    }

    // --- Validation de collection non vide ---
    public static <T extends Collection<?>> T requireNonEmpty(T collection, String collectionName) {
        if (collection == null || collection.isEmpty()) {
            throw RequiredValueException.forEmptyValue(collectionName);
        }
        return collection;
    }

    // --- Validation de map non vide ---
    public static <T extends Map<?, ?>> T requireNonEmpty(T map, String mapName) {
        if (map == null || map.isEmpty()) {
            throw RequiredValueException.forEmptyValue(mapName);
        }
        return map;
    }

    // --- Validation de nombre positif ---
    public static int requirePositive(int value, String valueName) {
        if (value <= 0) {
            throw RequiredValueException.forNegativeValue(valueName, value);
        }
        return value;
    }

    public static long requirePositive(long value, String valueName) {
        if (value <= 0) {
            throw RequiredValueException.forNegativeValue(valueName, value);
        }
        return value;
    }

    // --- Validation de condition personnalisée ---
    public static <T> T requireValid(T value, String valueName, Predicate<T> condition, String errorMessage) {
        if (value == null || !condition.test(value)) {
            throw RequiredValueException.forInvalidValue(valueName, value, errorMessage);
        }
        return value;
    }

    public static LocalDate requireValidDateOfBirth(LocalDate date) {
        requireNonNull(date, "dateOfBirth");
        if (date.isAfter(LocalDate.now())) {
            throw new IllegalArgumentException("La date de naissance doit être dans le passé");
        }
        return date;
    }

    public static String requireValidUrl(String url) {
        if (url == null) return null;
        if (!url.matches("^(https?|ftp)://[^\\s/$.?#].[^\\s]*$")) {
            throw new IllegalArgumentException("URL invalide: " + url);
        }
        return url;
    }
}
