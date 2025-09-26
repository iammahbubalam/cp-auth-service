package com.iammahbubalam.cp_auth_service.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.core.registry.EntryAddedEvent;
import io.github.resilience4j.core.registry.EntryRemovedEvent;
import io.github.resilience4j.core.registry.EntryReplacedEvent;
import io.github.resilience4j.core.registry.RegistryEventConsumer;
import io.github.resilience4j.retry.Retry;
import io.grpc.StatusRuntimeException;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeoutException;

@Configuration
@Slf4j
public class ResilienceConfig {




    @Bean
    public RegistryEventConsumer<CircuitBreaker> userServiceCircuitBreakerEventConsumer() {
        return new RegistryEventConsumer<>() {
            @Override
            public void onEntryAddedEvent(EntryAddedEvent<CircuitBreaker> entryAddedEvent) {
                CircuitBreaker circuitBreaker = entryAddedEvent.getAddedEntry();
                // Only attach listeners to the specific instance we care about
                if ("userService".equals(circuitBreaker.getName())) {
                    log.info("Attaching event listeners to Circuit Breaker '{}'", circuitBreaker.getName());
                    circuitBreaker.getEventPublisher()
                            .onStateTransition(event ->
                                    log.info("Circuit Breaker '{}' state transition: {} -> {}",
                                            circuitBreaker.getName(),
                                            event.getStateTransition().getFromState(),
                                            event.getStateTransition().getToState()))
                            .onCallNotPermitted(event ->
                                    log.warn("Circuit Breaker '{}' call not permitted in state: {}",
                                            circuitBreaker.getName(), circuitBreaker.getState()))
                            .onError(event ->
                                    log.error("Circuit Breaker '{}' error: '{}' after {}ms",
                                            circuitBreaker.getName(),
                                            event.getThrowable().toString(),
                                            event.getElapsedDuration().toMillis()));
                }
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
     * Configures event logging for the 'userService' Retry mechanism.
     */
    @Bean
    public RegistryEventConsumer<Retry> userServiceRetryEventConsumer() {
        return new RegistryEventConsumer<>() {
            @Override
            public void onEntryAddedEvent(EntryAddedEvent<Retry> entryAddedEvent) {
                Retry retry = entryAddedEvent.getAddedEntry();
                if ("userService".equals(retry.getName())) {
                    log.info("Attaching event listeners to Retry '{}'", retry.getName());
                    retry.getEventPublisher()
                            .onRetry(event ->
                                    log.warn("Retry '{}', attempt {}: Call failed with: {}",
                                            retry.getName(),
                                            event.getNumberOfRetryAttempts(),
                                            event.getLastThrowable().getMessage()))
                            .onSuccess(event ->
                                    log.info("Retry '{}' succeeded after {} attempt(s)",
                                            retry.getName(),
                                            event.getNumberOfRetryAttempts()));
                }
            }

            @Override
            public void onEntryRemovedEvent( EntryRemovedEvent<Retry> entryRemoveEvent) {
                // No-op
            }

            @Override
            public void onEntryReplacedEvent(EntryReplacedEvent<Retry> entryReplacedEvent) {
                // No-op
            }
        };
    }
}