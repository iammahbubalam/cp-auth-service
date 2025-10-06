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
    private UUID id;

    @Column("token_id")
    private UUID tokenId;

    @Column("user_id")
    private UUID userId;

    @Column("expires_at")
    private LocalDateTime expiresAt;

    @CreatedDate
    @Column("created_at")
    private LocalDateTime createdAt;

    @Column("is_revoked")
    private Boolean isRevoked;


    @Override
    public String toString() {
        return "RefreshToken{id=%s,tokenId=%s, userId=%s, expiresAt=%s, createdAt=%s, isRevoked=%s'}".formatted(id, tokenId, userId, expiresAt, createdAt, isRevoked);
    }
}
