package com.iammahbubalam.cp_auth_service.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import io.jsonwebtoken.lang.Collections;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .initialCapacity(100)
                .maximumSize(1000)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .recordStats()
        );
        cacheManager.setCacheNames(Collections.of("userCache", "roleCache", "publicKeyCache"));
        return cacheManager;
    }

    @Bean("userCacheBuilder")
    public Caffeine<Object, Object> userCacheBuilder() {
        return Caffeine.newBuilder()
                .initialCapacity(50)
                .maximumSize(5000)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .recordStats();
    }

    @Bean("roleCacheBuilder")
    public Caffeine<Object, Object> roleCacheBuilder() {
        return Caffeine.newBuilder()
                .initialCapacity(20)
                .maximumSize(1000)
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .recordStats();
    }

    @Bean("publicKeyCacheBuilder")
    public Caffeine<Object, Object> publicKeyCacheBuilder() {
        return Caffeine.newBuilder()
                .initialCapacity(5)
                .maximumSize(10)
                .expireAfterWrite(1, TimeUnit.HOURS)
                .recordStats();
    }
}
