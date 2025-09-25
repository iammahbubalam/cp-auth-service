package com.iammahbubalam.cp_auth_service.repository;

import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

public interface AuthUserRepository extends R2dbcRepository<AuthUser, UUID> {

    /**
     * Find user by username (case-insensitive)
     */
    @Query("SELECT * FROM auth_users WHERE LOWER(username) = LOWER(:username)")
    Mono<AuthUser> findByUsername(@Param("username") String username);

    /**
     * Find user by email (case-insensitive)
     */
    @Query("SELECT * FROM auth_users WHERE LOWER(email) = LOWER(:email)")
    Mono<AuthUser> findByEmail(@Param("email") String email);

    /**
     * Find user by email or username (case-insensitive)
     */
    @Query("SELECT * FROM auth_users WHERE LOWER(email) = LOWER(:emailOrUsername) OR LOWER(username) = LOWER(:emailOrUsername)")
    Mono<AuthUser> findByEmailOrUsername(@Param("emailOrUsername") String emailOrUsername);

    /**
     * Check if username exists (case-insensitive)
     */
    @Query("SELECT COUNT(*) > 0 FROM auth_users WHERE LOWER(username) = LOWER(:username)")
    Mono<Boolean> existsByUsername(@Param("username") String username);

    /**
     * Check if email exists (case-insensitive)
     */
    @Query("SELECT COUNT(*) > 0 FROM auth_users WHERE LOWER(email) = LOWER(:email)")
    Mono<Boolean> existsByEmail(@Param("email") String email);

    /**
     * Update last login timestamp
     */
    @Query("UPDATE auth_users SET last_login_at = :loginTime WHERE user_id = :userId")
    Mono<Void> updateLastLogin(@Param("userId") UUID userId, @Param("loginTime") LocalDateTime loginTime);

    /**
     * Update password hash
     */
    @Query("UPDATE auth_users SET password_hash = :passwordHash, updated_at = CURRENT_TIMESTAMP WHERE user_id = :userId")
    Mono<Void> updatePassword(@Param("userId") UUID userId, @Param("passwordHash") String passwordHash);

    /**
     * Update user role
     */
    @Query("UPDATE auth_users SET role = :role, updated_at = CURRENT_TIMESTAMP WHERE user_id = :userId")
    Mono<Void> updateRole(@Param("userId") UUID userId, @Param("role") String role);

    /**
     * Update user profile
     */
    @Query("UPDATE auth_users SET email = :email, username = :username, first_name = :firstName, last_name = :lastName, updated_at = CURRENT_TIMESTAMP WHERE user_id = :userId")
    Mono<Void> updateProfile(@Param("userId") UUID userId, @Param("email") String email,
                             @Param("username") String username, @Param("firstName") String firstName,
                             @Param("lastName") String lastName);

    /**
     * Activate/Deactivate user account
     */
    @Query("UPDATE auth_users SET is_active = :isActive, updated_at = CURRENT_TIMESTAMP WHERE user_id = :userId")
    Mono<Void> updateActiveStatus(@Param("userId") UUID userId, @Param("isActive") boolean isActive);

    /**
     * Find active users by role
     */
    @Query("SELECT * FROM auth_users WHERE role = :role AND is_active = true")
    Mono<AuthUser> findActiveUsersByRole(@Param("role") String role);
}