package com.iammahbubalam.cp_auth_service.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.core.registry.EntryAddedEvent;
import io.github.resilience4j.core.registry.EntryRemovedEvent;
import io.github.resilience4j.core.registry.EntryReplacedEvent;
import io.github.resilience4j.core.registry.RegistryEventConsumer;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryRegistry;
import io.github.resilience4j.timelimiter.TimeLimiter;
import io.github.resilience4j.timelimiter.TimeLimiterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Provides centralized, industry-grade configuration for Resilience4j event logging.
 * This class creates event consumers that attach loggers to EVERY resilience instance
 * (CircuitBreaker, Retry, TimeLimiter) created from the application.yml configuration,
 * ensuring complete observability across all downstream service communications.
 */
@Configuration
@Slf4j
public class ResilienceConfig {

    /**
     * Creates a bean that consumes Circuit Breaker registry events.
     * It attaches detailed loggers to every Circuit Breaker instance upon its creation.
     */
    @Bean
    public RegistryEventConsumer<CircuitBreaker> circuitBreakerEventConsumer() {
        return new RegistryEventConsumer<>() {
            @Override
            public void onEntryAddedEvent(EntryAddedEvent<CircuitBreaker> entryAddedEvent) {
                CircuitBreaker circuitBreaker = entryAddedEvent.getAddedEntry();
                log.info("Attaching log listeners to Circuit Breaker '{}'", circuitBreaker.getName());

                circuitBreaker.getEventPublisher()
                        .onStateTransition(event ->
                                log.warn("Circuit Breaker '{}' state changed: {} -> {}",
                                        event.getCircuitBreakerName(),
                                        event.getStateTransition().getFromState(),
                                        event.getStateTransition().getToState()))
                        .onCallNotPermitted(event ->
                                log.warn("Circuit Breaker '{}' call not permitted. Current state is {}.",
                                        event.getCircuitBreakerName(), circuitBreaker.getState()));
            }

            @Override
            public void onEntryRemovedEvent(EntryRemovedEvent<CircuitBreaker> entryRemoveEvent) {
            }

            @Override
            public void onEntryReplacedEvent(EntryReplacedEvent<CircuitBreaker> entryReplacedEvent) {
            }
        };
    }

    /**
     * Creates a bean that consumes Retry registry events.
     * It attaches a logger to every Retry instance to log retry attempts.
     */
    @Bean
    public RegistryEventConsumer<Retry> retryEventConsumer() {
        return new RegistryEventConsumer<>() {
            @Override
            public void onEntryAddedEvent(EntryAddedEvent<Retry> entryAddedEvent) {
                Retry retry = entryAddedEvent.getAddedEntry();
                log.info("Attaching log listeners to Retry '{}'", retry.getName());

                retry.getEventPublisher()
                        .onRetry(event ->
                                log.warn("Retry '{}', attempt {}: Call failed with: {}",
                                        event.getName(),
                                        event.getNumberOfRetryAttempts(),
                                        event.getLastThrowable().getMessage()));
            }

            @Override
            public void onEntryRemovedEvent(EntryRemovedEvent<Retry> entryRemoveEvent) {
            }

            @Override
            public void onEntryReplacedEvent(EntryReplacedEvent<Retry> entryReplacedEvent) {
            }
        };
    }

    /**
     * Creates a bean that consumes TimeLimiter registry events.
     * It attaches a logger to every TimeLimiter instance to log timeouts.
     */
    @Bean
    public RegistryEventConsumer<TimeLimiter> timeLimiterEventConsumer() {
        return new RegistryEventConsumer<>() {
            @Override
            public void onEntryAddedEvent(EntryAddedEvent<TimeLimiter> entryAddedEvent) {
                TimeLimiter timeLimiter = entryAddedEvent.getAddedEntry();
                log.info("Attaching log listeners to TimeLimiter '{}'", timeLimiter.getName());

                timeLimiter.getEventPublisher()
                        .onTimeout(event ->
                                log.error("TimeLimiter '{}' recorded a timeout event after {}ms",
                                        event.getTimeLimiterName(),
                                        timeLimiter.getTimeLimiterConfig().getTimeoutDuration().toMillis()));
            }

            @Override
            public void onEntryRemovedEvent(EntryRemovedEvent<TimeLimiter> entryRemoveEvent) {
            }

            @Override
            public void onEntryReplacedEvent(EntryReplacedEvent<TimeLimiter> entryReplacedEvent) {
            }
        };
    }

    @Bean
    public CircuitBreaker circuitBreaker(CircuitBreakerRegistry registry) {
        return registry.circuitBreaker("default");
    }

    @Bean
    public Retry retry(RetryRegistry registry) {
        return registry.retry("default");
    }

    @Bean
    public TimeLimiter timeLimiter(TimeLimiterRegistry registry) {
        return registry.timeLimiter("default");
    }
}