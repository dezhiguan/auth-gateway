package com.careermate.authgw.auth;

import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("dev")
public class DevAuthDataSeeder {

    public DevAuthDataSeeder(JdbcTemplate jdbcTemplate, PasswordHasher passwordHasher) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM auth_users WHERE username = ?",
                Integer.class,
                "admin");
        if (count != null && count > 0) {
            return;
        }
        jdbcTemplate.update("""
                        INSERT INTO auth_users(username, password_hash, platform_role, session_version, status, created_at)
                        VALUES (?, ?, 'ADMIN', 0, 'ACTIVE', now())
                        """,
                "admin",
                passwordHasher.hash("Admin123!"));
    }
}
