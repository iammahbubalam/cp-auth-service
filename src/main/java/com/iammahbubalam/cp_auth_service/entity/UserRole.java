package com.iammahbubalam.cp_auth_service.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table("user_roles")
public class UserRole {
    @Id
    private UUID id;

    @Column("user_id")
    private UUID userId;

    @Column("role")
    private String role;

    @Override
    public String toString() {
        return "UserRole{id=%s, userId=%s, role='%s'}".formatted(id, userId, role);
    }


}