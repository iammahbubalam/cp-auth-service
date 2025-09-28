package com.iammahbubalam.cp_auth_service.dto;


import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenPair {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
    private String tokenType;

    public TokenPair(String accessToken, String refreshToken, long accessTokenTtl) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = accessTokenTtl;
        this.tokenType = "Bearer";
    }

    @Override
    public String toString() {
        return "TokenPair{, expiresIn=%d, tokenType='%s'}".formatted(expiresIn, tokenType);
    }
}
