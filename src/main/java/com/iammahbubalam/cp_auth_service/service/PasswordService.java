package com.iammahbubalam.cp_auth_service.service;


import com.iammahbubalam.cp_auth_service.util.PasswordValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Service
@Slf4j
@RequiredArgsConstructor
public class PasswordService {


    private final PasswordEncoder passwordEncoder;


    private final PasswordValidator passwordValidator;


    public Mono<String> hashPassword(String plainPassword) {
        return Mono.fromCallable(() -> passwordEncoder.encode(plainPassword))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Boolean> verifyPassword(String plainPassword, String hashedPassword) {
        return Mono.fromCallable(() -> passwordEncoder.matches(plainPassword, hashedPassword))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Boolean> isValidPassword(String password) {
        return Mono.fromCallable(() -> passwordValidator.isValid(password));
    }

    public Mono<Boolean> isSecurePassword(String password) {
        return Mono.fromCallable(() -> passwordValidator.isSecure(password));
    }


    public Mono<String> getValidationMessage() {
        return Mono.fromCallable(passwordValidator::getValidationMessage);
    }

    public Mono<String> validateAndHashPassword(String plainPassword) {
        return isValidPassword(plainPassword)
                .flatMap(isValid -> {
                    if (!isValid) {
                        return Mono.error(new IllegalArgumentException(passwordValidator.getValidationMessage()));
                    }
                    return hashPassword(plainPassword);
                });
    }
}