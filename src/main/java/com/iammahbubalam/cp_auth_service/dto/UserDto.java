package com.iammahbubalam.cp_auth_service.dto;

import lombok.*;

import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private UUID userId;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Set<String> roles;
    private boolean isActive;

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public boolean hasAnyRole(Set<String> requiredRoles) {
        if (roles == null || requiredRoles == null) {
            return false;
        }
        return roles.stream().anyMatch(requiredRoles::contains);
    }

    @Override
    public String toString() {
        return "UserDto{userId=%s, username='%s', email='%s', firstName='%s', lastName='%s', roles=%s, isActive=%s, lastLoginAt=%s}".formatted(userId, username, email, firstName, lastName, roles, isActive);
    }
}
