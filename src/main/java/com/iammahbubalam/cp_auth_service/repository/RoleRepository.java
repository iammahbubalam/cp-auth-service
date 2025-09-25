package com.iammahbubalam.cp_auth_service.repository;

import com.iammahbubalam.cp_auth_service.entity.UserRole;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

 public interface RoleRepository extends R2dbcRepository<UserRole, UUID> {

        /**
         * Find all role assignments for a given user.
         * Spring Data can generate this query automatically from the method name.
         */
        Flux<UserRole> findByUserId(UUID userId);

        /**
         * Find a user's specific role assignment.
         * This is useful if a user can only have one of each role type.
         */
        Mono<UserRole> findByUserIdAndRole(UUID userId, String role);

        /**
         * Check if a specific user has a specific role (case-insensitive).
         * Corrected to query the 'user_roles' table.
         */
        @Query("SELECT COUNT(*) > 0 FROM user_roles WHERE user_id = :userId AND LOWER(role) = LOWER(:roleName)")
        Mono<Boolean> existsByUserIdAndRoleName(@Param("userId") UUID userId, @Param("roleName") String roleName);
}
