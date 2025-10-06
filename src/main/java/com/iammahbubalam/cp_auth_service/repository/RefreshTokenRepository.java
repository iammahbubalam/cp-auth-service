package com.iammahbubalam.cp_auth_service.repository;

import com.iammahbubalam.cp_auth_service.entity.RefreshToken;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends R2dbcRepository<RefreshToken, UUID> {

    /**
     * Find refresh token by token hash
     */
    @Query("SELECT * FROM refresh_tokens WHERE token_hash = :tokenHash AND is_revoked = false")
    Mono<RefreshToken> findByTokenHash(@Param("tokenHash") String tokenHash);

    /**
     * Find all active refresh tokens for a user
     */
    @Query("SELECT * FROM refresh_tokens WHERE user_id = :userId AND is_revoked = false AND expires_at > CURRENT_TIMESTAMP")
    Flux<RefreshToken> findActiveTokensByUserId(@Param("userId") UUID userId);

    /**
     * Revoke all refresh tokens for a user
     */
    @Query("UPDATE refresh_tokens SET is_revoked = true WHERE user_id = :userId AND is_revoked = false")
    Mono<Void> revokeAllTokensByUserId(@Param("userId") UUID userId);

    /**
     * Revoke specific refresh token
     */
    @Query("UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = :tokenHash")
    Mono<Void> revokeTokenByHash(@Param("tokenHash") String tokenHash);

    /**
     * Delete expired tokens (cleanup job)
     */
    @Query("DELETE FROM refresh_tokens WHERE expires_at < :cutoffTime")
    Mono<Void> deleteExpiredTokens(@Param("cutoffTime") LocalDateTime cutoffTime);

    /**
     * Count active tokens for a user
     */
    @Query("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = :userId AND is_revoked = false AND expires_at > CURRENT_TIMESTAMP")
    Mono<Long> countActiveTokensByUserId(@Param("userId") UUID userId);

    /**
     * Find token by hash including revoked ones
     */
    @Query("SELECT * FROM refresh_tokens WHERE token_hash = :tokenHash")
    Mono<RefreshToken> findByTokenHashIncludingRevoked(@Param("tokenHash") String tokenHash);

    Mono<RefreshToken> findByTokenId(UUID tokenId);
}