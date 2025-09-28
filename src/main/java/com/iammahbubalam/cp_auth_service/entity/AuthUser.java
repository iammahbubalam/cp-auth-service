package com.iammahbubalam.cp_auth_service.entity;


import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("auth_user")
public class AuthUser {
    @Id
    @Column("user_id")
    private UUID id;
    @Column("username")
    private String username;
    @Column("email")
    private String email;
    @Column("password")
    private String password;
    @Column("first_name")
    private String firstName;
    @Column("last_name")
    private String lastName;
    @Column("roles")
    private Set<UserRole> roles;
    @Column("is_active")
    private boolean isActive;
    @CreatedDate
    @Column("creation_date")
    private LocalDateTime creationDate;
    @LastModifiedDate
    @Column("last_modified_date")
    private LocalDateTime lastModifiedDate;


    @Override
    public String toString() {
        return "AuthUser{id=%s, username='%s', email='%s', password='%s', firstName='%s', lastName='%s', roles=%s, isActive=%s, creationDate=%s, lastModifiedDate=%s}".formatted(id, username, email, password, firstName, lastName, roles, isActive, creationDate, lastModifiedDate);
    }
}

