package com.careermate.authgw.auth;

public record AuthUser(
        long id,
        String phoneHash,
        String emailHash,
        String username,
        String passwordHash,
        String tenantId,
        String platformRole,
        long sessionVersion,
        String status) {
}
