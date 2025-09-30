package com.iammahbubalam.cp_auth_service.util;

import com.iammahbubalam.cp_auth_service.dto.UserDto;
import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import reactor.core.publisher.Mono;

import java.util.Set;

public class UserMapper {

    public static Mono<UserDto> toDto(AuthUser user, Set<String> roles) {
        if (user == null) {
            return Mono.empty();
        }
        UserDto dto = new UserDto(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                roles,
                user.isActive()
        );
        return Mono.just(dto);
    }

    public static Mono<AuthUser> toEntity(UserDto dto) {
        if (dto == null) {
            return Mono.empty();
        }
        AuthUser user = AuthUser.builder()
                .id(dto.getUserId())
                .username(dto.getUsername())
                .email(dto.getEmail())
                .firstName(dto.getFirstName())
                .lastName(dto.getLastName())
                .isActive(dto.isActive())
                .build();
        return Mono.just(user);
    }
}
