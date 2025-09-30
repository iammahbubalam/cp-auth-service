package com.iammahbubalam.cp_auth_service.service;

import com.iammahbubalam.cpAuthService.grpc.AuthServiceGrpc;
import com.iammahbubalam.cpAuthService.grpc.AuthServiceProto;
import com.iammahbubalam.cp_auth_service.dto.UserDto;
import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import com.iammahbubalam.cp_auth_service.entity.UserRole;
import com.iammahbubalam.cp_auth_service.exception.*;
import com.iammahbubalam.cp_auth_service.repository.AuthUserRepository;
import com.iammahbubalam.cp_auth_service.repository.RoleRepository;
import com.iammahbubalam.cp_auth_service.util.TokenUtils;
import com.iammahbubalam.cp_auth_service.util.UserMapper;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.timelimiter.TimeLimiter;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@GrpcService
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl extends AuthServiceGrpc.AuthServiceImplBase {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final RoleService roleService;
    private final AuthUserRepository authUserRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final UserServiceClient userServiceClient;
    private final CacheService cacheService;
    private final TokenBlacklistService blacklistService;
    private final PasswordEncoder passwordEncoder;
    private final CircuitBreaker circuitBreaker;
    private final Retry retry;
    private final TimeLimiter timeLimiter;
    private final PasswordService passwordService;


    @Override
    @Transactional
    public void register(AuthServiceProto.RegisterRequest request, StreamObserver<AuthServiceProto.RegisterResponse> responseObserver) {
        logger.info("Registration attempt for email: {}", request.getEmail());

        // Validation and registration flow
        validateRegistrationRequest(request)
                .flatMap(this::checkUserExistence)
                .flatMap(this::createAuthUser)
                .flatMap(this::createUserProfile)
                .flatMap(user -> UserMapper.toDto(user, Set.of("USER")))
                .flatMap(this::generateTokensForNewUser)
                .subscribe(
                        response -> {
                            logger.info("Registration successful for user: {}", response.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Registration failed for email: {}", request.getEmail(), error);
                        }
                );
    }

    @Override
    public void login(AuthServiceProto.LoginRequest request, StreamObserver<AuthServiceProto.LoginResponse> responseObserver) {
        logger.info("Login attempt for: {}", request.getEmailOrUsername());

        authenticateUser(request)
                .flatMap(authUser -> UserMapper.toDto(authUser, roleRepository.findByUserId(authUser.getId()).map(UserRole::getRole).collect(Collectors.toSet()).block()))
                .flatMap(this::generateTokensForLogin)
                .flatMap(this::cacheUserData)
                .subscribe(
                        response -> {
                            logger.info("Login successful for user: {}", response.getUserInfo().getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Login failed for: {}", request.getEmailOrUsername(), error);
                            responseObserver.onError(handleAuthError(error));
                        }
                );
    }

    @Override
    public void refreshToken(AuthServiceProto.RefreshTokenRequest request, StreamObserver<AuthServiceProto.RefreshTokenResponse> responseObserver) {
        logger.debug("Token refresh attempt");

        validateRefreshTokenAndGenerateNew(request)
                .subscribe(
                        response -> {
                            logger.debug("Token refresh successful");
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Token refresh failed", error);
                            responseObserver.onError(handleAuthError(error));
                        }
                );
    }

    @Override
    public void validateUser(AuthServiceProto.ValidateUserRequest request, StreamObserver<AuthServiceProto.ValidateUserResponse> responseObserver) {
        logger.debug("Token validation request");

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
                            logger.debug("Token validation failed", error);

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
        logger.debug("User existence check for: {}", request.getEmailOrUsername());

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
                            logger.error("User existence check failed", error);
                            responseObserver.onError(Status.INTERNAL
                                    .withDescription("Failed to check user existence")
                                    .asRuntimeException());
                        }
                );
    }

    @Override
    public void logout(AuthServiceProto.LogoutRequest request, StreamObserver<AuthServiceProto.LogoutResponse> responseObserver) {
        logger.info("Logout request received");

        performLogout(request)
                .subscribe(
                        response -> {
                            logger.info("Logout successful");
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Logout failed", error);
                            responseObserver.onError(handleAuthError(error));
                        }
                );
    }

    @Override
    public void roleCheck(AuthServiceProto.RoleCheckRequest request, StreamObserver<AuthServiceProto.RoleCheckResponse> responseObserver) {
        logger.debug("Role check request for role: {}", request.getRequiredRole());

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
                            logger.error("Role check failed", error);
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
        logger.info("Token revocation request: {}", request.getReason());

        revokeTokenById(request)
                .subscribe(
                        response -> {
                            logger.info("Token revoked successfully");
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Token revocation failed", error);
                            responseObserver.onError(handleAuthError(error));
                        }
                );
    }

    @Override
    public void changePassword(AuthServiceProto.ChangePasswordRequest request, StreamObserver<AuthServiceProto.ChangePasswordResponse> responseObserver) {
        logger.info("Password change request for user: {}", request.getUserId());

        performPasswordChange(request)
                .subscribe(
                        response -> {
                            logger.info("Password changed successfully for user: {}", request.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Password change failed for user: {}", request.getUserId(), error);
                            responseObserver.onError(handleAuthError(error));
                        }
                );
    }

    @Override
    public void updateUserRoles(AuthServiceProto.UpdateUserRolesRequest request, StreamObserver<AuthServiceProto.UpdateUserRolesResponse> responseObserver) {
        logger.info("Role update request for user: {}", request.getUserId());

        performRoleUpdate(request)
                .subscribe(
                        response -> {
                            logger.info("Roles updated successfully for user: {}", request.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Role update failed for user: {}", request.getUserId(), error);
                            responseObserver.onError(handleAuthError(error));
                        }
                );
    }

    @Override
    public void updateUserProfile(AuthServiceProto.UpdateUserProfileRequest request, StreamObserver<AuthServiceProto.UpdateUserProfileResponse> responseObserver) {
        logger.info("Profile update request for user: {}", request.getUserId());

        performProfileUpdate(request)
                .subscribe(
                        response -> {
                            logger.info("Profile updated successfully for user: {}", request.getUserId());
                            responseObserver.onNext(response);
                            responseObserver.onCompleted();
                        },
                        error -> {
                            logger.error("Profile update failed for user: {}", request.getUserId(), error);
                            responseObserver.onError(handleAuthError(error));
                        }
                );
    }


    private Mono<AuthServiceProto.RegisterRequest> validateRegistrationRequest(AuthServiceProto.RegisterRequest request) {
        if (request.getEmail().trim().isEmpty()) {
            return Mono.error(new IllegalArgumentException("Email is required"));
        }
        if (request.getUsername().trim().isEmpty()) {
            return Mono.error(new IllegalArgumentException("Username is required"));
        }
        if (request.getPassword().length() < 8) {
            return Mono.error(new IllegalArgumentException("Password must be at least 8 characters long"));
        }
        if (!request.getEmail().matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            return Mono.error(new IllegalArgumentException("Invalid email format"));
        }

        // Asynchronous password validation
        return passwordService.isValidPassword(request.getPassword())
                .flatMap(isValid -> {
                    if (!isValid) {
                        return passwordService.getValidationMessage()
                                .flatMap(msg -> Mono.error(new IllegalArgumentException(msg)));
                    }
                    return Mono.just(request);
                });
    }

    private Mono<AuthServiceProto.RegisterRequest> checkUserExistence(AuthServiceProto.RegisterRequest request) {
        return Mono.zip(
                authUserRepository.existsByEmail(request.getEmail()),
                authUserRepository.existsByUsername(request.getUsername())
        ).flatMap(tuple -> {
            boolean emailExists = tuple.getT1();
            boolean usernameExists = tuple.getT2();

            if (emailExists) {
                return Mono.error(new DuplicateUserException("User Already Exist With Email: " + request.getEmail()));
            }
            if (usernameExists) {
                return Mono.error(new DuplicateUserException("User Already Exist With UserName" + request.getUsername()));
            }
            return Mono.just(request);
        });
    }

    @Transactional
    protected Mono<AuthUser> createAuthUser(AuthServiceProto.RegisterRequest request) {
        return passwordService.hashPassword(request.getPassword())
                .map(hashedPassword -> AuthUser.builder()
                        .username(request.getUsername())
                        .email(request.getEmail())
                        .password(hashedPassword)
                        .firstName(request.getFirstName())
                        .lastName(request.getLastName())
                        .isActive(true)
                        .build())
                .flatMap(authUserRepository::save);
    }

    @Transactional
    protected Mono<UserRole> createUserRole(AuthUser user, String role) {
        UserRole userRole = UserRole.builder()
                .userId(user.getId())
                .role(role)
                .build();
        return roleRepository.save(userRole);
    }

    private Mono<AuthUser> createUserProfile(AuthUser authUser) {
        if (authUser == null) {
            return Mono.error(new IllegalArgumentException("authUser must not be null"));
        }
        return userServiceClient.createUser(
                authUser.getId(),
                authUser.getUsername(),
                authUser.getEmail(),
                authUser.getFirstName(),
                authUser.getLastName()
        ).flatMap(response -> {
            if (!userServiceClient.isSuccessResponse(response)) {
                logger.error("User service failed to create profile for userId={}: {}", authUser.getId(), userServiceClient.getResponseMessage(response));
                return authUserRepository.delete(authUser)
                        .then(Mono.error(new UserCreationException("Failed to create user profile: " +
                                userServiceClient.getResponseMessage(response))));
            }
            return Mono.just(authUser);
        }).onErrorResume(error -> {
            logger.error("Error during user profile creation for userId={}", authUser.getId(), error);
            return authUserRepository.delete(authUser)
                    .then(Mono.error(new UserCreationException("Failed to create user profile :" + error.getMessage())));
        });
    }

    private Mono<AuthServiceProto.RegisterResponse> generateTokensForNewUser(UserDto user) {
        return jwtService.generateTokenPair(user)
                .map(tokenPair -> {
                    AuthServiceProto.UserInfo userInfo = AuthServiceProto.UserInfo.newBuilder()
                            .setUserId(user.getUserId().toString())
                            .setUsername(user.getUsername())
                            .setEmail(user.getEmail())
                            .setFirstName(user.getFirstName() != null ? user.getFirstName() : "")
                            .setLastName(user.getLastName() != null ? user.getLastName() : "")
                            .addAllRoles(Set.of("USER"))
                            .setIsActive(user.isActive())
//                        .setCreatedAt(user.getCreationDate().toEpochSecond(java.time.ZoneOffset.UTC))
                            .build();

                    return AuthServiceProto.RegisterResponse.newBuilder()
                            .setSuccess(true)
                            .setUserId(user.getUserId().toString())
                            .setAccessToken(tokenPair.getAccessToken())
                            .setRefreshToken(tokenPair.getRefreshToken())
                            .setExpiresIn(tokenPair.getExpiresIn())
                            .setMessage("Registration successful")
                            .setUserInfo(userInfo)
                            .build();
                });
    }

    private Mono<AuthUser> authenticateUser(AuthServiceProto.LoginRequest request) {
        return authUserRepository.findByEmailOrUsername(request.getEmailOrUsername())
                .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid email or username")))
                .flatMap(user -> {
                    if (!user.isActive()) {
                        return Mono.error(new DisabledException("Account is deactivated"));
                    }

                    return passwordService.verifyPassword(request.getPassword(), user.getPassword())
                            .flatMap(matches -> {
                                if (!matches) {
                                    return Mono.error(new BadCredentialsException("Invalid password"));
                                }
                                return Mono.just(user);
                            });
                });
    }

    private Mono<AuthServiceProto.LoginResponse> generateTokensForLogin(UserDto user) {
        return jwtService.generateTokenPair(user)
                .map(tokenPair -> {
                    AuthServiceProto.UserInfo userInfo = AuthServiceProto.UserInfo.newBuilder()
                            .setUserId(user.getUserId().toString())
                            .setUsername(user.getUsername())
                            .setEmail(user.getEmail())
                            .setFirstName(user.getFirstName() != null ? user.getFirstName() : "")
                            .setLastName(user.getLastName() != null ? user.getLastName() : "")
                            .addAllRoles(user.getRoles())
                            .setIsActive(user.isActive())
//                            .setCreatedAt(user.getCreatedAt().toEpochSecond(java.time.ZoneOffset.UTC))
//                            .setLastLoginAt(user.getLastLoginAt() != null ?
//                                    user.getLastLoginAt().toEpochSecond(java.time.ZoneOffset.UTC) : 0)
                            .build();

                    return AuthServiceProto.LoginResponse.newBuilder()
                            .setSuccess(true)
                            .setAccessToken(tokenPair.getAccessToken())
                            .setRefreshToken(tokenPair.getRefreshToken())
                            .setExpiresIn(tokenPair.getExpiresIn())
                            .setMessage("Login successful")
                            .setUserInfo(userInfo)
                            .build();
                });
    }

    private Mono<AuthServiceProto.LoginResponse> cacheUserData(AuthServiceProto.LoginResponse response) {
        UUID userId = UUID.fromString(response.getUserInfo().getUserId());

        UserDto userContext = new UserDto(
                userId,
                response.getUserInfo().getUsername(),
                response.getUserInfo().getEmail(),
                response.getUserInfo().getFirstName(),
                response.getUserInfo().getLastName(),
                (Set<String>) response.getUserInfo().getRolesList(),
                response.getUserInfo().getIsActive()
        );

        return cacheService.cacheUserDto(userId, userContext)
                .then(Mono.just(response));
    }

    private Mono<AuthServiceProto.RefreshTokenResponse> validateRefreshTokenAndGenerateNew(AuthServiceProto.RefreshTokenRequest request) {
        return jwtService.validateRefreshToken(request.getRefreshToken())
                .flatMap(userContext ->
                        authUserRepository.findById(userContext.getUserId())
                                .switchIfEmpty(Mono.error(new UserNotFoundException("User not found")))
                )
                .flatMap(user -> {
                    if (!user.isActive()) {
                        return Mono.error(new DisabledException("Account is deactivated"));
                    }

                    // Blacklist old refresh token and generate new tokens
                    String oldTokenId = TokenUtils.extractTokenId(request.getRefreshToken());
                    LocalDateTime tokenExpiration = LocalDateTime.now().plusDays(30);

                    return blacklistService.blacklistRefreshToken(oldTokenId, tokenExpiration)
                            .then(
                                    roleRepository.findByUserId(user.getId())
                                            .map(UserRole::getRole)
                                            .collect(Collectors.toSet())
                                            .flatMap(roles -> UserMapper.toDto(user, roles))
                                            .flatMap(userDto -> jwtService.generateTokenPair(userDto)
                                                    .map(tokenPair -> AuthServiceProto.RefreshTokenResponse.newBuilder()
                                                            .setSuccess(true)
                                                            .setAccessToken(tokenPair.getAccessToken())
                                                            .setRefreshToken(tokenPair.getRefreshToken())
                                                            .setExpiresIn(tokenPair.getExpiresIn())
                                                            .setMessage("Token refreshed successfully")
                                                            .build()
                                                    )
                                            )
                            );
                });
    }

    private Mono<AuthServiceProto.LogoutResponse> performLogout(AuthServiceProto.LogoutRequest request) {
        String accessTokenId = TokenUtils.extractTokenId(request.getAccessToken());
        String refreshTokenId = TokenUtils.extractTokenId(request.getRefreshToken());

        LocalDateTime accessTokenExpiration = LocalDateTime.now().plusHours(1);
        LocalDateTime refreshTokenExpiration = LocalDateTime.now().plusDays(30);

        return Mono.when(
                blacklistService.blacklistAccessToken(accessTokenId, accessTokenExpiration),
                blacklistService.blacklistRefreshToken(refreshTokenId, refreshTokenExpiration)
        ).then(Mono.just(AuthServiceProto.LogoutResponse.newBuilder()
                .setSuccess(true)
                .setMessage("Logout successful")
                .build()));
    }

    private Mono<AuthServiceProto.RevokeTokenResponse> revokeTokenById(AuthServiceProto.RevokeTokenRequest request) {
        String tokenId = TokenUtils.extractTokenId(request.getToken());
        LocalDateTime expiration = LocalDateTime.now().plusDays(30); // Safe upper bound

        return blacklistService.blacklistAccessToken(tokenId, expiration)
                .then(blacklistService.blacklistRefreshToken(tokenId, expiration))
                .then(Mono.just(AuthServiceProto.RevokeTokenResponse.newBuilder()
                        .setSuccess(true)
                        .setMessage("Token revoked successfully")
                        .build()));
    }

    private Mono<AuthServiceProto.ChangePasswordResponse> performPasswordChange(AuthServiceProto.ChangePasswordRequest request) {
        UUID userId = UUID.fromString(request.getUserId());

        return authUserRepository.findById(userId)
                .switchIfEmpty(Mono.error(new UserNotFoundException("User not found")))
                .flatMap(user ->
                        passwordService.verifyPassword(request.getCurrentPassword(), user.getPassword())
                                .flatMap(matches -> {
                                    if (!matches) {
                                        return Mono.error(new BadCredentialsException("Current password is incorrect"));
                                    }
                                    return passwordService.validateAndHashPassword(request.getNewPassword());
                                })
                                .flatMap(newPasswordHash ->
                                        authUserRepository.updatePassword(userId, newPasswordHash)
                                )
                                .then(cacheService.evictAllUserCache(userId))
                                .then(Mono.just(AuthServiceProto.ChangePasswordResponse.newBuilder()
                                        .setSuccess(true)
                                        .setMessage("Password changed successfully")
                                        .build()))
                );
    }

    private Mono<AuthServiceProto.UpdateUserRolesResponse> performRoleUpdate(AuthServiceProto.UpdateUserRolesRequest request) {
        UUID userId = UUID.fromString(request.getUserId());
        String newRole = request.getRolesList().isEmpty() ? "USER" : request.getRolesList().get(0);

        return roleService.isValidRole(newRole)
                .flatMap(isValid -> {
                    if (!isValid) {
                        return Mono.error(new BadCredentialsException("Invalid role: " + newRole));
                    }

                    return authUserRepository.updateRole(userId, newRole)
                            .then(cacheService.evictAllUserCache(userId))
                            .then(Mono.just(AuthServiceProto.UpdateUserRolesResponse.newBuilder()
                                    .setSuccess(true)
                                    .setMessage("Role updated successfully")
                                    .build()));
                });
    }

    private Mono<AuthServiceProto.UpdateUserProfileResponse> performProfileUpdate(AuthServiceProto.UpdateUserProfileRequest request) {
        UUID userId = UUID.fromString(request.getUserId());

        return authUserRepository.updateProfile(
                        userId,
                        request.getEmail(),
                        request.getUsername(),
                        request.getFirstName(),
                        request.getLastName()
                )
                .then(userServiceClient.updateUser(
                        userId,
                        request.getUsername(),
                        request.getEmail(),
                        request.getFirstName(),
                        request.getLastName()
                ))
                .flatMap(response -> {
                    if (!userServiceClient.isSuccessResponse(response)) {
                        return Mono.error(new UserCreationException("Failed to update user profile: " +
                                userServiceClient.getResponseMessage(response)));
                    }
                    return cacheService.evictAllUserCache(userId);
                })
                .then(Mono.just(AuthServiceProto.UpdateUserProfileResponse.newBuilder()
                        .setSuccess(true)
                        .setMessage("Profile updated successfully")
                        .build()));
    }

    private Throwable handleAuthError(Throwable error) {
        switch (error) {
            case DuplicateUserException duplicateUserException -> {
                return Status.ALREADY_EXISTS.withDescription(error.getMessage()).asException();
            }
            case BadCredentialsException badCredentialsException -> {
                return Status.UNAUTHENTICATED.withDescription(error.getMessage()).asException();
            }
            case TokenExpiredException tokenExpiredException -> {
                return Status.UNAUTHENTICATED.withDescription(error.getMessage()).asException();
            }
            case IllegalArgumentException illegalArgumentException -> {
                return Status.INVALID_ARGUMENT.withDescription(error.getMessage()).asRuntimeException();
            }
            case null, default -> {
                logger.error("Unexpected error in auth service", error);
                return Status.INTERNAL.withDescription("Internal server error").asException();
            }
        }
    }


}

