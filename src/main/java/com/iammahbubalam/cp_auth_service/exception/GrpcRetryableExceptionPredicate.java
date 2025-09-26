package com.iammahbubalam.cp_auth_service.exception;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;

import java.util.function.Predicate;

/**
 * A predicate to determine if a gRPC exception is retryable.
 * It returns 'true' for transient errors and 'false' for definitive errors.
 */
public class GrpcRetryableExceptionPredicate implements Predicate<Throwable> {

    @Override
    public boolean test(Throwable throwable) {
        // We only care about gRPC's StatusRuntimeException
        if (!(throwable instanceof StatusRuntimeException exception)) {
            // For non-gRPC exceptions, let the default behavior apply (e.g., IOException)
            return false;
        }

        Status.Code code = exception.getStatus().getCode();

        // These are typically transient, network-related, or server-side issues.
        // It makes sense to retry them.
        return switch (code) {
            case UNAVAILABLE, INTERNAL, UNIMPLEMENTED, DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED ->
                    true; // RETRY these errors

            // These are definitive client-side or data errors. Retrying will not help.
            case INVALID_ARGUMENT, NOT_FOUND, ALREADY_EXISTS, PERMISSION_DENIED, UNAUTHENTICATED, FAILED_PRECONDITION,
                 CANCELLED, ABORTED, OUT_OF_RANGE -> false; // DO NOT RETRY these errors

            default ->
                // For any other gRPC status, we default to not retrying.
                    false;
        };
    }
}