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
        if (!(throwable instanceof StatusRuntimeException exception)) {
            return false;
        }

        Status.Code code = exception.getStatus().getCode();


        return switch (code) {
            case UNAVAILABLE, INTERNAL, UNIMPLEMENTED, DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED ->
                    true;
            // These are definitive client-side or data errors. Retrying will not help.
            case INVALID_ARGUMENT, NOT_FOUND, ALREADY_EXISTS, PERMISSION_DENIED, UNAUTHENTICATED, FAILED_PRECONDITION,
                 CANCELLED, ABORTED, OUT_OF_RANGE -> false;

            default ->
                    false;
        };
    }
}