package com.iammahbubalam.cp_auth_service.entity;

import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table("refresh_tokens")
public class RefreshToken {
    @Id
    @Column("token_id")
    private UUID tokenId;

    @Column("user_id")
    private UUID userId;

    @Column("token_hash")
    private String tokenHash;

    @Column("expires_at")
    private LocalDateTime expiresAt;

    @CreatedDate
    @Column("created_at")
    private LocalDateTime createdAt;

    @Column("is_revoked")
    private Boolean isRevoked;

    @Column("device")
    private String device; // JSON string

    @Override
    public String toString() {
        return "RefreshToken{tokenId=%s, userId=%s, tokenHash='%s', expiresAt=%s, createdAt=%s, isRevoked=%s, deviceInfo='%s'}".formatted(tokenId, userId, tokenHash, expiresAt, createdAt, isRevoked, device);
    }
}
