package com.iammahbubalam.cp_auth_service.service;
import com.iammahbubalam.cpAuthService.grpc.AuthServiceGrpc;
import com.iammahbubalam.cpAuthService.grpc.AuthServiceProto;
import com.iammahbubalam.cp_auth_service.entity.UserRole;
import com.iammahbubalam.cp_auth_service.repository.AuthUserRepository;
import com.iammahbubalam.cp_auth_service.repository.RoleRepository;
import com.iammahbubalam.cp_auth_service.util.UserMapper;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.stream.Collectors;

@GrpcService
@Slf4j
@RequiredArgsConstructor
public class AuthServiceGrpcImpl extends AuthServiceGrpc.AuthServiceImplBase {

    private final RoleService roleService;
    private final AuthUserRepository authUserRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final AuthService authService;

    @Override
    public void register(AuthServiceProto.RegisterRequest request, StreamObserver<AuthServiceProto.RegisterResponse> responseObserver) {

        log.info("Registration attempt for email: {}", request.getEmail());
        authService.validateRegistrationRequest(request)
                .flatMap(authService::checkUserExistence)
                .flatMap(authService::createAuthUser)
//                .flatMap(this::createUserProfile)
                .flatMap(user -> authService.createUserRole(user.getId(), "USER")
                        .map(role -> reactor.util.function.Tuples.of(user, role))
                )
                .flatMap(tuple -> UserMapper.toDto(tuple.getT1(), Set.of(tuple.getT2().getRole())))
                .flatMap(authService::generateTokensForNewUser)
                .subscribe(
                        response -> {
                            log.info("Registration successful for user: {}", response.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Registration failed for email: {}", request.getEmail(), error);
                        }
                );
    }

    @Override
    public void login(AuthServiceProto.LoginRequest request, StreamObserver<AuthServiceProto.LoginResponse> responseObserver) {
        log.info("Login attempt for: {}", request.getEmailOrUsername());

        authService.authenticateUser(request)
                .flatMap(authUser ->
                        roleRepository.findByUserId(authUser.getId())
                                .map(UserRole::getRole)
                                .collect(Collectors.toSet())
                                .flatMap(roles -> UserMapper.toDto(authUser, roles))
                )
                .flatMap(authService::generateTokensForLogin)
                .flatMap(authService::cacheUserData)
                .doOnNext(response ->
                        log.info("Login successful for user: {}", response.getUserInfo().getUserId())
                )
                .doOnError(error ->
                        log.error("Login failed for: {}", request.getEmailOrUsername(), error)
                )
                .onErrorResume(error ->
                        Mono.error(authService.handleAuthError(error))
                )
                .subscribe(
                        responseObserver::onNext,
                        responseObserver::onError,
                        responseObserver::onCompleted
                );
    }

    @Override
    public void refreshToken(AuthServiceProto.RefreshTokenRequest request, StreamObserver<AuthServiceProto.RefreshTokenResponse> responseObserver) {
        log.debug("Token refresh attempt");

        authService.validateRefreshTokenAndGenerateNew(request)
                .subscribe(
                        response -> {
                            log.debug("Token refresh successful");
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Token refresh failed", error);
                            responseObserver.onError(authService.handleAuthError(error));
                        }
                );
    }

    @Override
    public void validateUser(AuthServiceProto.ValidateUserRequest request, StreamObserver<AuthServiceProto.ValidateUserResponse> responseObserver) {
        log.debug("Token validation request");

        jwtService.validateToken(request.getToken())
                .subscribe(
                        userContext -> {
                            AuthServiceProto.ValidateUserResponse response = AuthServiceProto.ValidateUserResponse.newBuilder()
                                    .setValid(true)
                                    .setUserId(userContext.getUserId().toString())
                                    .setUsername(userContext.getUsername())
                                    .setEmail(userContext.getEmail())
                                    .addAllRoles(userContext.getRoles())
                                    .setMessage("Token is valid")
                                    .build();

                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.debug("Token validation failed", error);

                            AuthServiceProto.ValidateUserResponse response = AuthServiceProto.ValidateUserResponse.newBuilder()
                                    .setValid(false)
                                    .setMessage("Invalid or expired token")
                                    .build();

                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        }
                );
    }

    @Override
    public void isUserExist(AuthServiceProto.UserExistRequest request, StreamObserver<AuthServiceProto.UserExistResponse> responseObserver) {
        log.debug("User existence check for: {}", request.getEmailOrUsername());

        authUserRepository.findByEmailOrUsername(request.getEmailOrUsername())
                .map(user -> AuthServiceProto.UserExistResponse.newBuilder()
                        .setExists(true)
                        .setUserId(user.getId().toString())
                        .build())
                .switchIfEmpty(Mono.just(AuthServiceProto.UserExistResponse.newBuilder()
                        .setExists(false)
                        .build()))
                .subscribe(
                        response -> {
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("User existence check failed", error);
                            responseObserver.onError(Status.INTERNAL
                                    .withDescription("Failed to check user existence")
                                    .asRuntimeException());
                        }
                );
    }

    @Override
    public void logout(AuthServiceProto.LogoutRequest request, StreamObserver<AuthServiceProto.LogoutResponse> responseObserver) {
        log.info("Logout request received");

        authService.performLogout(request)
                .subscribe(
                        response -> {
                            log.info("Logout successful");
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Logout failed", error);
                            responseObserver.onError(authService.handleAuthError(error));
                        }
                );
    }

    @Override
    public void roleCheck(AuthServiceProto.RoleCheckRequest request, StreamObserver<AuthServiceProto.RoleCheckResponse> responseObserver) {
        log.debug("Role check request for role: {}", request.getRequiredRole());

        jwtService.validateToken(request.getToken())
                .flatMap(userContext ->
                        roleService.hasRole(userContext, request.getRequiredRole())
                                .map(hasRole -> AuthServiceProto.RoleCheckResponse.newBuilder()
                                        .setAuthorized(hasRole)
                                        .addAllUserRoles(userContext.getRoles())
                                        .setMessage(hasRole ? "Access granted" : "Insufficient privileges")
                                        .build())
                )
                .subscribe(
                        response -> {
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Role check failed", error);
                            AuthServiceProto.RoleCheckResponse response = AuthServiceProto.RoleCheckResponse.newBuilder()
                                    .setAuthorized(false)
                                    .setMessage("Token validation failed")
                                    .build();
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        }
                );
    }

    @Override
    public void revokeToken(AuthServiceProto.RevokeTokenRequest request, StreamObserver<AuthServiceProto.RevokeTokenResponse> responseObserver) {
        log.info("Token revocation request: {}", request.getReason());

        authService.revokeTokenById(request)
                .subscribe(
                        response -> {
                            log.info("Token revoked successfully");
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Token revocation failed", error);
                            responseObserver.onError(authService.handleAuthError(error));
                        }
                );
    }

    @Override
    public void changePassword(AuthServiceProto.ChangePasswordRequest request, StreamObserver<AuthServiceProto.ChangePasswordResponse> responseObserver) {
        log.info("Password change request for user: {}", request.getUserId());

        authService.performPasswordChange(request)
                .subscribe(
                        response -> {
                            log.info("Password changed successfully for user: {}", request.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Password change failed for user: {}", request.getUserId(), error);
                            responseObserver.onError(authService.handleAuthError(error));
                        }
                );
    }

    @Override
    public void updateUserRoles(AuthServiceProto.UpdateUserRolesRequest request, StreamObserver<AuthServiceProto.UpdateUserRolesResponse> responseObserver) {
        log.info("Role update request for user: {}", request.getUserId());

        authService.performRoleUpdate(request)
                .subscribe(
                        response -> {
                            log.info("Roles updated successfully for user: {}", request.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Role update failed for user: {}", request.getUserId(), error);
                            responseObserver.onError(authService.handleAuthError(error));
                        }
                );
    }

    @Override
    public void updateUserProfile(AuthServiceProto.UpdateUserProfileRequest request, StreamObserver<AuthServiceProto.UpdateUserProfileResponse> responseObserver) {
        log.info("Profile update request for user: {}", request.getUserId());

        authService.performProfileUpdate(request)
                .subscribe(
                        response -> {
                            log.info("Profile updated successfully for user: {}", request.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            log.error("Profile update failed for user: {}", request.getUserId(), error);
                            responseObserver.onError(authService.handleAuthError(error));
                        }
                );
    }
}

