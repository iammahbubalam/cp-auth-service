package com.iammahbubalam.cp_auth_service.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

public class TokenUtils {

    public static String extractTokenId(String bearerToken) {
        try{
            DecodedJWT jwt = JWT.decode(bearerToken);
            return jwt.getId();
        }catch (JWTDecodeException e){
           throw new JWTVerificationException("Invalid  token", e);
        }
    }
    public static String extractSubject(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getSubject();
        } catch (JWTVerificationException e) {
            return null;
        }
    }
    public static Date extractExpiration(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getExpiresAt();
        } catch (JWTVerificationException e) {
            return null;
        }
    }
    public static boolean isTokenExpired(String token) {
        Date expiration = extractExpiration(token);
        return expiration != null && expiration.before(new Date());
    }
    public static String generateTokenId() {
        return UUID.randomUUID().toString();
    }

    public static long getCurrentTimestamp() {
        return Instant.now().getEpochSecond();
    }


    public static long getExpirationTimestamp(long ttlSeconds) {
        return getCurrentTimestamp() + ttlSeconds;
    }



    public static boolean isValidUUID(String uuid) {
        try {
            UUID.fromString(uuid);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static String maskToken(String token) {
        if (token == null || token.length() < 10) {
            return "***";
        }
        return token.substring(0, 4) + "***" + token.substring(token.length() - 4);
    }



















}
