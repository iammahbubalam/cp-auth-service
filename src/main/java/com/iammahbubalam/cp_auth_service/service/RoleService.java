package com.iammahbubalam.cp_auth_service.service;

import com.iammahbubalam.cp_auth_service.dto.UserDto;
import io.jsonwebtoken.lang.Collections;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Set;
@Service
public class RoleService {
    private static final Set<String> VALID_ROLES = Collections.setOf("USER", "ADMIN", "MODERATOR");
    private static final Set<String> ADMIN_ROLES = Collections.setOf("ADMIN");
    private static final Set<String> MODERATOR_ROLES = Collections.setOf("ADMIN", "MODERATOR");


    public Mono<Boolean> hasRole(UserDto userDto, String requiredRole) {
        return Mono.fromCallable(() -> {
            if (userDto == null || userDto.getRoles() == null) {
                return false;
            }

            return userDto.getRoles().contains(requiredRole);
        });
    }

    public Mono<Boolean> hasAnyRole(UserDto userDto, Set<String> requiredRoles) {
        return Mono.fromCallable(() -> {
            if (userDto == null || userDto.getRoles() == null || requiredRoles == null) {
                return false;
            }

            return userDto.getRoles().stream()
                    .anyMatch(requiredRoles::contains);
        });
    }

    public Mono<Boolean> isAdmin(UserDto userDto) {
        return hasAnyRole(userDto, ADMIN_ROLES);
    }

    public Mono<Boolean> isModerator(UserDto userDto) {
        return hasAnyRole(userDto, MODERATOR_ROLES);
    }

    public Mono<Boolean> isValidRole(String role) {
        return Mono.fromCallable(() -> {
            if (role == null) {
                return false;
            }
            return VALID_ROLES.contains(role.toUpperCase());
        });
    }


    public Mono<String> getDefaultRole() {
        return Mono.just("USER");
    }


    public Mono<Boolean> canManageRoles(UserDto userDto) {
        return isAdmin(userDto);
    }

    public Mono<Integer> getRoleLevel(String role) {
        return Mono.fromCallable(() -> {
            return switch (role.toUpperCase()) {
                case "ADMIN" -> 3;
                case "MODERATOR" -> 2;
                case "USER" -> 1;
                default -> 0;
            };
        });
    }

    public Mono<Boolean> canManageRole(String sourceRole, String targetRole) {
        return Mono.zip(getRoleLevel(sourceRole), getRoleLevel(targetRole))
                .map(tuple -> tuple.getT1() > tuple.getT2());
    }
}
