package com.iammahbubalam.cp_auth_service.util;

import com.iammahbubalam.cp_auth_service.dto.UserDto;
import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import com.iammahbubalam.cp_auth_service.exception.UserNotFoundException;
import io.r2dbc.spi.Row;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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

    public static Mono<UserDto> toDtoWithRoles(Flux<Row> rowsFlux) {
        return rowsFlux.collectList()
                .handle((rows, sink) -> {
                    if (rows.isEmpty()) {
                        sink.error(new UserNotFoundException("User not found"));
                        return;
                    }
                    Row firstRow = rows.getFirst();
                    UserDto userDto = UserDto.builder()
                            .userId(firstRow.get("user_id", UUID.class))
                            .username(firstRow.get("username", String.class))
                            .email(firstRow.get("email", String.class))
                            .firstName(firstRow.get("first_name", String.class))
                            .lastName(firstRow.get("last_name", String.class))
                            .isActive(Boolean.TRUE.equals(firstRow.get("is_active", Boolean.class)))
                            .build();

                    Set<String> roles = rows.stream()
                            .map(row -> row.get("role", String.class))
                            .filter(Objects::nonNull)
                            .distinct()
                            .collect(Collectors.toSet());

                    userDto.setRoles(new HashSet<>(roles));
                    sink.next(userDto);
                });
    }
}
