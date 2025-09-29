package com.iammahbubalam.cp_auth_service.exception;

public class TokenBlacklistException extends RuntimeException {
    public TokenBlacklistException(String message) {
        super(message);
    }
}
