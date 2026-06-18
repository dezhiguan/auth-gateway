package com.careermate.authgw.auth;

public record TokenPair(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn) {
}
