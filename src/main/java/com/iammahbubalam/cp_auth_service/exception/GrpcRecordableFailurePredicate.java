package com.iammahbubalam.cp_auth_service.exception;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;

import java.util.function.Predicate;

/**
 * A predicate to determine if a gRPC exception should be recorded as a failure
 * by the Circuit Breaker.
 */
public class GrpcRecordableFailurePredicate implements Predicate<Throwable> {

    @Override
    public boolean test(Throwable throwable) {
        if (!(throwable instanceof StatusRuntimeException exception)) {
            return false; // Let the 'record-exceptions' list handle non-gRPC errors.
        }

        Status.Code code = exception.getStatus().getCode();

        // These codes indicate a server-side or network failure.
        // They should count against the service's health.
        return switch (code) {
            case UNAVAILABLE, INTERNAL, UNIMPLEMENTED, DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED ->
                    true; // Count as failure

            // Client-side errors should NOT count as a server failure.
            default -> false;
        };
    }
}