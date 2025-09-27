package com.iammahbubalam.cp_auth_service.exception;

import io.grpc.*;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class GrpcExceptionInterceptor implements ServerInterceptor {
    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call,
                                                                 Metadata headers,
                                                                 ServerCallHandler<ReqT, RespT> next) {
        ServerCall.Listener<ReqT> listener = next.startCall(call, headers);

        return new ForwardingServerCallListener.SimpleForwardingServerCallListener<ReqT>(listener) {
            @Override
            public void onHalfClose() {
                try {
                    super.onHalfClose();
                } catch (IllegalArgumentException | OtpInvalidException e) {
                    log.warn("Invalid argument: {}", e.getMessage());
                    call.close(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e), new Metadata());
                } catch (BadCredentialsException | TokenInvalidException | TokenExpiredException e) {
                    log.warn("Unauthenticated: {}", e.getMessage());
                    call.close(Status.UNAUTHENTICATED.withDescription(e.getMessage()).withCause(e), new Metadata());
                } catch (DisabledException | AccessDeniedException e) {
                    log.warn("Permission denied: {}", e.getMessage());
                    call.close(Status.PERMISSION_DENIED.withDescription(e.getMessage()).withCause(e), new Metadata());
                } catch (UserNotFoundException e) {
                    log.warn("Not found: {}", e.getMessage());
                    call.close(Status.NOT_FOUND.withDescription(e.getMessage()).withCause(e), new Metadata());
                } catch (DuplicateUserException e) {
                    log.warn("Already exists: {}", e.getMessage());
                    call.close(Status.ALREADY_EXISTS.withDescription(e.getMessage()).withCause(e), new Metadata());
                } catch (Exception e) {
                    log.error("Internal error: {}", e.getMessage(), e);
                    call.close(Status.INTERNAL.withDescription("Internal server error").withCause(e), new Metadata());
                }
            }
    };
    }}

