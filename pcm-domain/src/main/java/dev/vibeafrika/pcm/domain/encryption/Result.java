package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * Functional result type for error handling without exceptions.
 * Represents either a success value or an error.
 *
 * @param <T> The success value type
 * @param <E> The error type
 */
public abstract class Result<T, E> {

    private Result() {
        // Prevent external subclassing
    }

    /**
     * Creates a successful result.
     */
    public static <T, E> Result<T, E> success(T value) {
        return new Success<>(value);
    }

    /**
     * Creates a failed result.
     */
    public static <T, E> Result<T, E> failure(E error) {
        return new Failure<>(error);
    }

    /**
     * Returns true if this is a success result.
     */
    public abstract boolean isSuccess();

    /**
     * Returns true if this is a failure result.
     */
    public boolean isFailure() {
        return !isSuccess();
    }

    /**
     * Gets the success value if present.
     */
    public abstract Optional<T> getValue();

    /**
     * Gets the error if present.
     */
    public abstract Optional<E> getError();

    /**
     * Maps the success value to a new type.
     */
    public abstract <U> Result<U, E> map(Function<T, U> mapper);

    /**
     * Flat maps the success value to a new result.
     */
    public abstract <U> Result<U, E> flatMap(Function<T, Result<U, E>> mapper);

    /**
     * Maps the error to a new type.
     */
    public abstract <F> Result<T, F> mapError(Function<E, F> mapper);

    private static final class Success<T, E> extends Result<T, E> {
        private final T value;

        private Success(T value) {
            this.value = Objects.requireNonNull(value, "Success value cannot be null");
        }

        @Override
        public boolean isSuccess() {
            return true;
        }

        @Override
        public Optional<T> getValue() {
            return Optional.of(value);
        }

        @Override
        public Optional<E> getError() {
            return Optional.empty();
        }

        @Override
        public <U> Result<U, E> map(Function<T, U> mapper) {
            return Result.success(mapper.apply(value));
        }

        @Override
        public <U> Result<U, E> flatMap(Function<T, Result<U, E>> mapper) {
            return mapper.apply(value);
        }

        @Override
        public <F> Result<T, F> mapError(Function<E, F> mapper) {
            return Result.success(value);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Success<?, ?> success = (Success<?, ?>) o;
            return Objects.equals(value, success.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(value);
        }

        @Override
        public String toString() {
            return "Success{" + value + "}";
        }
    }

    private static final class Failure<T, E> extends Result<T, E> {
        private final E error;

        private Failure(E error) {
            this.error = Objects.requireNonNull(error, "Error cannot be null");
        }

        @Override
        public boolean isSuccess() {
            return false;
        }

        @Override
        public Optional<T> getValue() {
            return Optional.empty();
        }

        @Override
        public Optional<E> getError() {
            return Optional.of(error);
        }

        @Override
        public <U> Result<U, E> map(Function<T, U> mapper) {
            return Result.failure(error);
        }

        @Override
        public <U> Result<U, E> flatMap(Function<T, Result<U, E>> mapper) {
            return Result.failure(error);
        }

        @Override
        public <F> Result<T, F> mapError(Function<E, F> mapper) {
            return Result.failure(mapper.apply(error));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Failure<?, ?> failure = (Failure<?, ?>) o;
            return Objects.equals(error, failure.error);
        }

        @Override
        public int hashCode() {
            return Objects.hash(error);
        }

        @Override
        public String toString() {
            return "Failure{" + error + "}";
        }
    }
}
