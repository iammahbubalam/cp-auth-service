package com.iammahbubalam.cp_auth_service.service;

import com.iammahbubalam.cp_auth_service.dto.UserDto;
import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import com.iammahbubalam.cp_auth_service.entity.UserRole;
import com.iammahbubalam.cp_auth_service.repository.AuthUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Collections;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class CacheService {

    private static final String USER_CACHE_PREFIX = "user_cache:";
    private static final String ROLE_CACHE_PREFIX = "role_cache:";
    private static final Duration USER_CACHE_TTL = Duration.ofMinutes(5);
    private static final Duration ROLE_CACHE_TTL = Duration.ofMinutes(10);


    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final AuthUserRepository authUserRepository;


    public Mono<UserDto> getUserDto(UUID userId) {
        return getCachedUserDto(userId)
                .switchIfEmpty(
                        loadUserFromDatabase(userId)
                                .flatMap(userContext ->
                                        cacheUserDto(userId, userContext)
                                                .thenReturn(userContext)
                                )
                                .doOnNext(userContext -> log.debug("Loaded and cached user context: {}", userId))
                )
                .doOnNext(userContext -> log.debug("Cache-aside pattern resolved user context: {}", userId))
                .onErrorResume(error -> {
                    log.warn("Failed to get user context for: {} - {}", userId, error.getMessage());
                    return Mono.empty();
                });


    }

    private Mono<UserDto> loadUserFromDatabase(UUID userId) {
        return authUserRepository.findById(userId)
                .map(this::convertToUserDto)
                .doOnNext(userDto -> log.debug("Loaded user context from database: {}", userId))
                .onErrorResume(error -> {
                    log.error("Failed to load user from database: {}", userId, error);
                    return Mono.empty();
                });
    }

    private UserDto convertToUserDto(AuthUser authUser) {
        return UserDto.builder()
                .userId(authUser.getId())
                .username(authUser.getUsername())
                .email(authUser.getEmail())
                .firstName(authUser.getFirstName())
                .lastName(authUser.getLastName())
                .roles(
                        authUser.getRoles().stream()
                                .map(UserRole::getRole)
                                .collect(java.util.stream.Collectors.toSet())
                )
                .isActive(authUser.isActive())
                .build();

    }

    public Mono<Void> cacheUserDto(UUID userId, UserDto userDto) {
        String key = USER_CACHE_PREFIX + userId.toString();

        return redisTemplate.opsForValue()
                .set(key, userDto, USER_CACHE_TTL)
                .retryWhen(Retry.backoff(3, Duration.ofMillis(100)))
                .doOnSuccess(result -> log.debug("Cached user context for: {}", userId))
                .doOnError(error -> log.warn("Failed to cache user context for: {}", userId, error))
                .then()
                .onErrorResume(throwable -> {
                    log.warn("Cache operation failed, continuing without cache for user: {}", userId);
                    return Mono.empty();
                });
    }
    public Mono<UserDto> getCachedUserDto(UUID userId) {
        String key = USER_CACHE_PREFIX + userId.toString();

        return redisTemplate.opsForValue()
                .get(key)
                .cast(UserDto.class)
                .retryWhen(Retry.backoff(2, Duration.ofMillis(50)))
                .doOnNext(result -> log.debug("Cache hit for user: {}", userId))
                .doOnError(error -> log.warn("Failed to get cached user context for: {}", userId, error))
                .onErrorResume(throwable -> {
                    log.debug("Cache miss or error for user: {} - {}", userId, throwable.getMessage());
                    return Mono.empty();
                });
    }

    public Mono<Void> evictUserDto(UUID userId) {
        String key = USER_CACHE_PREFIX + userId.toString();

        return redisTemplate.delete(key)
                .retryWhen(Retry.backoff(2, Duration.ofMillis(50)))
                .doOnSuccess(result -> log.debug("Evicted user cache for: {}", userId))
                .doOnError(error -> log.warn("Failed to evict user cache for: {}", userId, error))
                .then()
                .onErrorResume(throwable -> {
                    log.warn("Cache eviction failed for user: {}", userId);
                    return Mono.empty();
                });
    }

    public Mono<Void> cacheUserRoles(UUID userId, String roles) {
        String key = ROLE_CACHE_PREFIX + userId.toString();

        return redisTemplate.opsForValue()
                .set(key, roles, ROLE_CACHE_TTL)
                .retryWhen(Retry.backoff(3, Duration.ofMillis(100)))
                .doOnSuccess(result -> log.debug("Cached user roles for: {}", userId))
                .doOnError(error -> log.warn("Failed to cache user roles for: {}", userId, error))
                .then()
                .onErrorResume(throwable -> Mono.empty());
    }

    /**
     * Get cached user roles (Reactive)
     */
    public Mono<String> getCachedUserRoles(UUID userId) {
        String key = ROLE_CACHE_PREFIX + userId.toString();

        return redisTemplate.opsForValue()
                .get(key)
                .cast(String.class)
                .retryWhen(Retry.backoff(2, Duration.ofMillis(50)))
                .doOnNext(result -> log.debug("Role cache hit for user: {}", userId))
                .doOnError(error -> log.warn("Failed to get cached user roles for: {}", userId, error))
                .onErrorResume(throwable -> Mono.empty());
    }

    /**
     * Evict user roles from cache (Reactive)
     */
    public Mono<Void> evictUserRoles(UUID userId) {
        String key = ROLE_CACHE_PREFIX + userId.toString();

        return redisTemplate.delete(key)
                .retryWhen(Retry.backoff(2, Duration.ofMillis(50)))
                .doOnSuccess(result -> log.debug("Evicted role cache for: {}", userId))
                .doOnError(error -> log.warn("Failed to evict role cache for: {}", userId, error))
                .then()
                .onErrorResume(throwable -> Mono.empty());
    }

    /**
     * Evict all cached data for a user (Reactive)
     */
    public Mono<Void> evictAllUserCache(UUID userId) {
        return Mono.when(
                        evictUserDto(userId),
                        evictUserRoles(userId)
                ).then()
                .doOnSuccess(result -> log.debug("Evicted all cache for user: {}", userId));
    }

    /**
     * Refresh user cache with latest database data (Reactive)
     */
    public Mono<UserDto> refreshUserCache(UUID userId) {
        return evictUserDto(userId)
                .then(getUserDto(userId))
                .doOnNext(userContext -> log.debug("Refreshed cache for user: {}", userId));
    }

    /**
     * Check if cache is available (Reactive Health Check)
     */
    public Mono<Boolean> isCacheAvailable() {
        return redisTemplate.hasKey("health_check")
                .timeout(Duration.ofSeconds(1))
                .doOnNext(available -> log.debug("Cache availability: {}", available))
                .onErrorReturn(false);
    }

    /**
     * Warm up cache with frequently accessed users (Reactive)
     */
    public Mono<Void> warmUpCache(java.util.List<UUID> userIds) {
        return reactor.core.publisher.Flux.fromIterable(userIds)
                .flatMap(this::getUserDto, 5) // Concurrency of 5
                .then()
                .doOnSuccess(result -> log.info("Cache warm-up completed for {} users", userIds.size()))
                .doOnError(error -> log.warn("Cache warm-up failed", error));
    }
}