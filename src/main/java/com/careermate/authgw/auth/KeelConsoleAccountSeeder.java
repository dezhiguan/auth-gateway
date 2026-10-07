package com.careermate.authgw.auth;

import java.util.List;
import org.springframework.context.annotation.DependsOn;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * 控制台本期只有一个账号，写在网关里，不提供注册。
 * 密码只在启动时哈希后入库，登录页没有找回密码。
 */
@Component
@DependsOn("flywayInitializer")
public class KeelConsoleAccountSeeder {

    static final String USERNAME = "guandezhi";
    static final String PASSWORD = "03180934xx.";

    public KeelConsoleAccountSeeder(JdbcTemplate jdbcTemplate, PasswordHasher passwordHasher,
                                     MembershipRepository membershipRepository) {
        String passwordHash = passwordHasher.hash(PASSWORD);
        Long userId = findUserId(jdbcTemplate);
        if (userId == null) {
            jdbcTemplate.update("""
                            INSERT INTO auth_users(username, password_hash, platform_role, session_version, status, created_at)
                            VALUES (?, ?, 'ADMIN', 0, 'ACTIVE', now())
                            """,
                    USERNAME, passwordHash);
            userId = findUserId(jdbcTemplate);
        } else {
            jdbcTemplate.update("""
                            UPDATE auth_users
                            SET password_hash = ?, platform_role = 'ADMIN', status = 'ACTIVE'
                            WHERE id = ?
                            """,
                    passwordHash, userId);
        }
        if (userId != null) {
            membershipRepository.ensureMembership(userId, "keel", "ADMIN");
        }
    }

    private static Long findUserId(JdbcTemplate jdbcTemplate) {
        List<Long> ids = jdbcTemplate.queryForList(
                "SELECT id FROM auth_users WHERE username = ? LIMIT 1", Long.class, USERNAME);
        return ids.isEmpty() ? null : ids.getFirst();
    }
}
