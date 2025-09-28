package com.iammahbubalam.cp_auth_service.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.iammahbubalam.cp_auth_service.dto.TokenPair;
import com.iammahbubalam.cp_auth_service.dto.UserDto;
import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import com.iammahbubalam.cp_auth_service.entity.UserRole;
import com.iammahbubalam.cp_auth_service.exception.TokenBlacklistException;
import com.iammahbubalam.cp_auth_service.exception.TokenInvalidException;
import com.iammahbubalam.cp_auth_service.util.TokenUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {
    @Value("${app.jwt.token.issuer}")
    private String issuer;

    @Value("${app.jwt.token.expiration.access:3600}")
    private long accessTokenTtl; // 1 hour

    @Value("${app.jwt.token.expiration.refresh:2592000}")
    private long refreshTokenTtl;

    private final SecurityKeyManager securityKeyManager;
    private final TokenBlacklistService tokenBlacklistService;

    public Mono<TokenPair> generateTokenPair(AuthUser user) {
        return Mono.fromCallable(

                () ->{
       try{
           Algorithm algorithm = Algorithm.RSA256(
                   (RSAPublicKey) securityKeyManager.getPublicKey(),
                   (RSAPrivateKey) securityKeyManager.getPrivateKey()
           );

           String accessToken = generateAccessToken(user, algorithm);
           String refreshToken = generateRefreshToken(user, algorithm);
           return new TokenPair(accessToken, refreshToken, accessTokenTtl);
       }catch (Exception e){
           log.error("Failed to generate token pair for user: {}", user.getId(), e);
           throw new RuntimeException("Token generation failed", e);
       }}
        );
    }

    private String generateAccessToken(AuthUser user, Algorithm algorithm) {
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(user.getId().toString())
                .withClaim("username", user.getUsername())
                .withClaim("email", user.getEmail())
                .withClaim("firstName", user.getFirstName())
                .withClaim("lastName", user.getLastName())
                .withClaim("roles", Collections.singletonList(user.getRoles()))
                .withClaim("isActive", user.isActive())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + (accessTokenTtl * 1000)))
                .withJWTId(TokenUtils.generateTokenId())
                .sign(algorithm);
    }

    private String generateRefreshToken(AuthUser user, Algorithm algorithm) {
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(user.getId().toString())
                .withClaim("type", "refresh")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + (refreshTokenTtl * 1000)))
                .withJWTId(TokenUtils.generateTokenId())
                .sign(algorithm);
    }

    public Mono<UserDto> validateToken(String token) {
        return Mono.fromCallable(() -> {
                    try {
                        Algorithm algorithm = Algorithm.RSA256(
                                (RSAPublicKey) securityKeyManager.getPublicKey(),
                                null // Only public key needed for verification
                        );

                        JWTVerifier verifier = JWT.require(algorithm)
                                .withIssuer(issuer)
                                .build();

                        DecodedJWT jwt = verifier.verify(token);

                        return extractUserDto(jwt);

                    } catch (JWTVerificationException e) {
                        log.debug("Invalid JWT token: {}", e.getMessage());
                        throw new TokenInvalidException("Invalid JWT token: {}"+ e.getMessage());
                    }
                })
                .flatMap(userContext -> {
                    // Check if token is blacklisted
                    String tokenId = TokenUtils.extractTokenId(token);
                    return tokenBlacklistService.isTokenBlacklisted(tokenId)
                            .flatMap(isBlacklisted -> {
                                if (isBlacklisted) {
                                    return Mono.error(new TokenBlacklistException("Token Is Blacklisted"));
                                }
                                return Mono.just(userContext);
                            });
                });
    }

    private UserDto extractUserDto(DecodedJWT jwt) {
        Set<String> roles = Set.copyOf(jwt.getClaim("roles").asList(String.class));
        return UserDto.builder()
                .userId(java.util.UUID.fromString(jwt.getSubject()))
                .username(jwt.getClaim("username").asString())
                        .email(jwt.getClaim("email").asString())
                        .firstName(jwt.getClaim("firstName").asString())
                        .lastName(jwt.getClaim("lastName").asString())
                        .roles(!roles.isEmpty() ? roles : io.jsonwebtoken.lang.Collections.setOf("USER"))
                        .isActive(jwt.getClaim("isActive").asBoolean() != null ? jwt.getClaim("isActive").asBoolean() : true)
                        .build();
    }

    public Mono<UserDto> validateRefreshToken(String refreshToken) {
        return Mono.fromCallable(() -> {
                    try {
                        Algorithm algorithm = Algorithm.RSA256(
                                (RSAPublicKey) securityKeyManager.getPublicKey(),
                                null
                        );

                        JWTVerifier verifier = JWT.require(algorithm)
                                .withIssuer(issuer)
                                .withClaim("type", "refresh")
                                .build();

                        DecodedJWT jwt = verifier.verify(refreshToken);

                        UserDto userDto = new UserDto();
                        userDto.setUserId(java.util.UUID.fromString(jwt.getSubject()));

                        return userDto;

                    } catch (JWTVerificationException e) {
                        log.debug("Invalid refresh token: {}", e.getMessage());
                        throw new TokenInvalidException("Invalid refresh token: {}"+ e.getMessage());
                    }
                })
                .flatMap(userDto -> {
                    String tokenId = TokenUtils.extractTokenId(refreshToken);
                    return tokenBlacklistService.isTokenBlacklisted(tokenId)
                            .flatMap(isBlacklisted -> {
                                if (isBlacklisted) {
                                    return Mono.error(new TokenBlacklistException("Token Is Blacklisted"));
                                }
                                return Mono.just(userDto);
                            });
                });
    }
    public Mono<LocalDateTime> getTokenExpiration(String token) {
        return Mono.fromCallable(() -> {
            Date expiration = TokenUtils.extractExpiration(token);
            if (expiration != null) {
                return LocalDateTime.ofInstant(expiration.toInstant(), ZoneOffset.UTC);
            }
            return null;
        });
    }

    public Mono<Boolean> isTokenExpired(String token) {
        return Mono.fromCallable(() -> TokenUtils.isTokenExpired(token));
    }
}
