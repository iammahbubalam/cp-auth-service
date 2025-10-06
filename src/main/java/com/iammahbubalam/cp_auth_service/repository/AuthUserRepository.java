package com.iammahbubalam.cp_auth_service.repository;

import com.iammahbubalam.cp_auth_service.entity.AuthUser;
import io.r2dbc.spi.Row;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface AuthUserRepository extends R2dbcRepository<AuthUser, UUID> {

    /**
     * Find user by username (case-insensitive)
     */
    @Query("SELECT * FROM auth_user WHERE LOWER(username) = LOWER(:username)")
    Mono<AuthUser> findByUsername(@Param("username") String username);

    /**
     * Find user by email (case-insensitive)
     */
    @Query("SELECT * FROM auth_user WHERE LOWER(email) = LOWER(:email)")
    Mono<AuthUser> findByEmail(@Param("email") String email);

    /**
     * Find user by email or username (case-insensitive)
     */
    @Query("SELECT * FROM auth_user WHERE LOWER(email) = LOWER(:emailOrUsername) OR LOWER(username) = LOWER(:emailOrUsername)")
    Mono<AuthUser> findByEmailOrUsername(@Param("emailOrUsername") String emailOrUsername);

    /**
     * Check if username exists (case-insensitive)
     */
    @Query("SELECT COUNT(*) > 0 FROM auth_user WHERE LOWER(username) = LOWER(:username)")
    Mono<Boolean> existsByUsername(@Param("username") String username);

    /**
     * Check if email exists (case-insensitive)
     */
    @Query("SELECT COUNT(*) > 0 FROM auth_user WHERE LOWER(email) = LOWER(:email)")
    Mono<Boolean> existsByEmail(@Param("email") String email);


    /**
     * Update password hash
     */
    @Query("UPDATE auth_user SET password = :passwordHash, last_modified_date = CURRENT_TIMESTAMP WHERE user_id = :userId")
    Mono<Void> updatePassword(@Param("userId") UUID userId, @Param("passwordHash") String passwordHash);


    /**
     * Update user profile
     */
    @Query("UPDATE auth_user SET email = :email, username = :username, first_name = :firstName, last_name = :lastName, last_modified_date = CURRENT_TIMESTAMP WHERE user_id = :userId")
    Mono<Void> updateProfile(@Param("userId") UUID userId, @Param("email") String email,
                             @Param("username") String username, @Param("firstName") String firstName,
                             @Param("lastName") String lastName);

    /**
     * Activate/Deactivate user account
     */
    @Query("UPDATE auth_user SET is_active = :isActive, last_modified_date = CURRENT_TIMESTAMP WHERE user_id = :userId")
    Mono<Void> updateActiveStatus(@Param("userId") UUID userId, @Param("isActive") boolean isActive);


    @Query("""
                SELECT u.*, r.role
                FROM auth_user u
                LEFT JOIN user_roles r ON u.user_id = r.user_id
                WHERE u.user_id = :userId
            """)
    Flux<Row> findUserWithRolesRaw(@Param("userId") UUID userId);

}