package com.iammahbubalam.cp_auth_service.config;

import com.iammahbubalam.cp_auth_service.exception.GrpcExceptionInterceptor;
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GrpcServerConfig {

    @GrpcGlobalServerInterceptor
    GrpcExceptionInterceptor grpcExceptionInterceptor() {
        return new GrpcExceptionInterceptor();
    }
}