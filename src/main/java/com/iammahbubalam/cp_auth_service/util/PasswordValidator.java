package com.iammahbubalam.cp_auth_service.util;


import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class PasswordValidator {

    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 128;

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%%*?&])[A-Za-z\\d@$!%%*?&]{%d,%d}$".formatted(MIN_LENGTH, MAX_LENGTH)
    );


    public boolean isValid(String password) {
        if (password == null || password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            return false;
        }
        return PASSWORD_PATTERN.matcher(password).matches();
    }

    public String getValidationMessage() {
        return "Password must be 8-128 characters long and contain at least one lowercase letter, " +
                "one uppercase letter, one digit, and one special character (@$!%*?&)";
    }

    public boolean isSecure(String password) {
        if (!isValid(password)) {
            return false;
        }

        // Additional security checks
        return !containsCommonPatterns(password) &&
                !containsRepeatingCharacters(password);
    }

    private boolean containsCommonPatterns(String password) {
        String lower = password.toLowerCase();
        String[] commonPatterns = {"password", "123456", "qwerty", "admin", "user"};

        for (String pattern : commonPatterns) {
            if (lower.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsRepeatingCharacters(String password) {
        char previousChar = 0;
        int repeatCount = 1;

        for (char c : password.toCharArray()) {
            if (c == previousChar) {
                repeatCount++;
                if (repeatCount >= 3) {
                    return true;
                }
            } else {
                repeatCount = 1;
                previousChar = c;
            }
        }
        return false;
    }
}
