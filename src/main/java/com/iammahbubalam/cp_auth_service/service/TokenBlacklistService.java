package com.iammahbubalam.cp_auth_service.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenBlacklistService {
    private static final String BLACKLIST_PREFIX = "blacklist:";
    private static final String ACCESS_TOKEN_PREFIX = "access:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh:";

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public Mono<Void> blacklistAccessToken(String tokenId, LocalDateTime expirationTime) {
        String key = BLACKLIST_PREFIX + ACCESS_TOKEN_PREFIX + tokenId;
        Duration ttl = Duration.between(LocalDateTime.now(), expirationTime);

        if (ttl.isNegative()) {
            // Token already expired, no need to blacklist
            return Mono.empty();
        }

        return redisTemplate.opsForValue()
                .set(key, "revoked", ttl)
                .doOnSuccess(result -> log.debug("Blacklisted access token: {}", tokenId))
                .doOnError(error -> log.error("Failed to blacklist access token: {}", tokenId, error))
                .then();
    }

    public Mono<Void> blacklistRefreshToken(String tokenId, LocalDateTime expirationTime) {
        String key = BLACKLIST_PREFIX + REFRESH_TOKEN_PREFIX + tokenId;
        Duration ttl = Duration.between(LocalDateTime.now(), expirationTime);

        if (ttl.isNegative()) {
            // Token already expired, no need to blacklist
            return Mono.empty();
        }

        return redisTemplate.opsForValue()
                .set(key, "revoked", ttl)
                .doOnSuccess(result -> log.debug("Blacklisted refresh token: {}", tokenId))
                .doOnError(error -> log.error("Failed to blacklist refresh token: {}", tokenId, error))
                .then();
    }

    public Mono<Boolean> isTokenBlacklisted(String tokenId) {
        if (tokenId == null) {
            return Mono.just(false);
        }

        // Check both access and refresh token blacklists
        String accessKey = BLACKLIST_PREFIX + ACCESS_TOKEN_PREFIX + tokenId;
        String refreshKey = BLACKLIST_PREFIX + REFRESH_TOKEN_PREFIX + tokenId;

        return Mono.zip(
                        redisTemplate.hasKey(accessKey),
                        redisTemplate.hasKey(refreshKey)
                ).map(tuple -> tuple.getT1() || tuple.getT2())
                .doOnError(error -> log.error("Failed to check token blacklist for: {}", tokenId, error))
                .onErrorReturn(false); // If Redis is down, assume token is not blacklisted
    }
}
