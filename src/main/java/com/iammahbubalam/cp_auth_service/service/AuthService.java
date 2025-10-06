package com.iammahbubalam.cp_auth_service.service;

import com.iammahbubalam.cpAuthService.grpc.AuthServiceProto;
import com.iammahbubalam.cp_auth_service.dto.UserDto;
import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import com.iammahbubalam.cp_auth_service.entity.UserRole;
import com.iammahbubalam.cp_auth_service.exception.*;
import com.iammahbubalam.cp_auth_service.repository.AuthUserRepository;
import com.iammahbubalam.cp_auth_service.repository.RefreshTokenRepository;
import com.iammahbubalam.cp_auth_service.repository.RoleRepository;
import com.iammahbubalam.cp_auth_service.util.TokenUtils;
import com.iammahbubalam.cp_auth_service.util.UserMapper;
import io.grpc.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final RoleService roleService;
    private final AuthUserRepository authUserRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final UserServiceClient userServiceClient;
    private final CacheService cacheService;
    private final TokenBlacklistService blacklistService;
    private final PasswordService passwordService;
    private final RefreshTokenRepository refreshTokenRepository;


    protected Mono<AuthServiceProto.RegisterRequest> validateRegistrationRequest(AuthServiceProto.RegisterRequest request) {
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

    protected Mono<AuthServiceProto.RegisterRequest> checkUserExistence(AuthServiceProto.RegisterRequest request) {
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
    protected Mono<UserRole> createUserRole(UUID userId, String role) {
        UserRole userRole = UserRole.builder()
                .userId(userId)
                .role(role)
                .build();
        return roleRepository.save(userRole);
    }

    protected Mono<AuthUser> createUserProfile(AuthUser authUser) {
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
                log.error("User service failed to create profile for userId={}: {}", authUser.getId(), userServiceClient.getResponseMessage(response));
                return authUserRepository.delete(authUser)
                        .then(Mono.error(new UserCreationException("Failed to create user profile: " +
                                userServiceClient.getResponseMessage(response))));
            }
            return Mono.just(authUser);
        }).onErrorResume(error -> {
            log.error("Error during user profile creation for userId={}", authUser.getId(), error);
            return authUserRepository.delete(authUser)
                    .then(Mono.error(new UserCreationException("Failed to create user profile :" + error.getMessage())));
        });
    }

    protected Mono<AuthServiceProto.RegisterResponse> generateTokensForNewUser(UserDto user) {
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

    protected Mono<AuthUser> authenticateUser(AuthServiceProto.LoginRequest request) {
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

    protected Mono<AuthServiceProto.LoginResponse> generateTokensForLogin(UserDto user) {
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

    protected Mono<AuthServiceProto.LoginResponse> cacheUserData(AuthServiceProto.LoginResponse response) {
        UUID userId = UUID.fromString(response.getUserInfo().getUserId());

        Set<String> roles = new HashSet<>(response.getUserInfo().getRolesList());

        UserDto userDto = UserDto.builder()
                .userId(userId)
                .username(response.getUserInfo().getUsername())
                .email(response.getUserInfo().getEmail())
                .firstName(response.getUserInfo().getFirstName())
                .lastName(response.getUserInfo().getLastName())
                .roles(roles)
                .isActive(response.getUserInfo().getIsActive())
                .build();

        return cacheService.cacheUserDto(userId, userDto)
                .then(Mono.just(response));
    }

    protected Mono<AuthServiceProto.RefreshTokenResponse> validateRefreshTokenAndGenerateNew(AuthServiceProto.RefreshTokenRequest request) {
        return jwtService.validateRefreshToken(request.getRefreshToken())
                .flatMap(userDto ->
                        authUserRepository.findById(userDto.getUserId())
                                .switchIfEmpty(Mono.error(new UserNotFoundException("User not found")))
                )
                .flatMap(user -> {
                    if (!user.isActive()) {
                        return Mono.error(new DisabledException("Account is deactivated"));
                    }
                    String oldTokenId = TokenUtils.extractTokenId(request.getRefreshToken());
                    LocalDateTime tokenExpiration = Objects.requireNonNull(TokenUtils.extractExpiration(request.getRefreshToken())).toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
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

    protected Mono<AuthServiceProto.LogoutResponse> performLogout(AuthServiceProto.LogoutRequest request) {
        String accessToken = request.getAccessToken();
        String refreshToken = request.getRefreshToken();

        String accessTokenId = TokenUtils.extractTokenId(accessToken);
        String refreshTokenId = TokenUtils.extractTokenId(refreshToken);

        // Extract userId from token (adjust as needed)
        UUID userId = UUID.fromString(Objects.requireNonNull(TokenUtils.extractSubject(accessToken)));

        LocalDateTime accessTokenExpiration = Objects.requireNonNull(TokenUtils.extractExpiration(accessToken))
                .toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        LocalDateTime refreshTokenExpiration = Objects.requireNonNull(TokenUtils.extractExpiration(refreshToken))
                .toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

        return jwtService.revokeAllUserRefreshTokens(userId)
                .then(
                        Mono.when(
                                blacklistService.blacklistAccessToken(accessTokenId, accessTokenExpiration),
                                blacklistService.blacklistRefreshToken(refreshTokenId, refreshTokenExpiration)
                        )
                )
                .then(Mono.just(AuthServiceProto.LogoutResponse.newBuilder()
                        .setSuccess(true)
                        .setMessage("Logout successful")
                        .build()));
    }

    protected Mono<AuthServiceProto.RevokeTokenResponse> revokeTokenById(AuthServiceProto.RevokeTokenRequest request) {
        String tokenId = TokenUtils.extractTokenId(request.getToken());
        LocalDateTime expiration = LocalDateTime.now().plusDays(30); // Safe upper bound

        return blacklistService.blacklistAccessToken(tokenId, expiration)
                .then(blacklistService.blacklistRefreshToken(tokenId, expiration))
                .then(Mono.just(AuthServiceProto.RevokeTokenResponse.newBuilder()
                        .setSuccess(true)
                        .setMessage("Token revoked successfully")
                        .build()));
    }

    protected Mono<AuthServiceProto.ChangePasswordResponse> performPasswordChange(AuthServiceProto.ChangePasswordRequest request) {
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

    protected Mono<AuthServiceProto.UpdateUserRolesResponse> performRoleUpdate(AuthServiceProto.UpdateUserRolesRequest request) {
        UUID userId = UUID.fromString(request.getUserId());
        String newRole = request.getRolesList().isEmpty() ? "USER" : request.getRolesList().getFirst();

        return roleService.isValidRole(newRole)
                .flatMap(isValid -> {
                    if (!isValid) {
                        return Mono.error(new BadCredentialsException("Invalid role: " + newRole));
                    }
                    // Fetch existing roles
                    return roleRepository.findByUserId(userId)
                            .collectList()
                            .flatMap(existingRoles -> {
                                boolean alreadyHasRole = existingRoles.stream()
                                        .anyMatch(role -> role.getRole().equalsIgnoreCase(newRole));
                                if (!alreadyHasRole) {
                                    UserRole userRole = UserRole.builder()
                                            .userId(userId)
                                            .role(newRole)
                                            .build();
                                    return roleRepository.save(userRole).then();
                                }
                                return Mono.empty();
                            })
                            .then(cacheService.evictAllUserCache(userId))
                            .then(Mono.just(AuthServiceProto.UpdateUserRolesResponse.newBuilder()
                                    .setSuccess(true)
                                    .setMessage("Role updated successfully")
                                    .build()));
                });
    }

    protected Mono<AuthServiceProto.UpdateUserProfileResponse> performProfileUpdate(AuthServiceProto.UpdateUserProfileRequest request) {
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

    protected Throwable handleAuthError(Throwable error) {
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
                log.error("Unexpected error in auth service", error);
                return Status.INTERNAL.withDescription("Internal server error").asException();
            }
        }
    }
}
