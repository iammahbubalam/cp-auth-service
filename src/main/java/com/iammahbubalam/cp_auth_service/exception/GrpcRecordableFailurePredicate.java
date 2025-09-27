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
            return false;
        }

        Status.Code code = exception.getStatus().getCode();
        return switch (code) {
            case UNAVAILABLE, INTERNAL, UNIMPLEMENTED, DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED ->
                    true;
            default -> false;
        };
    }
}