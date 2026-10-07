package com.careermate.authgw.auth;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.DependsOn;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * 控制台本期只有一个账号，不提供注册。
 * 密码只从环境变量 KEEL_CONSOLE_PASSWORD 读取，不写进代码或镜像。未配置时不覆盖库里已有的口令。
 */
@Component
@DependsOn("flywayInitializer")
public class KeelConsoleAccountSeeder {

    private static final Logger log = LoggerFactory.getLogger(KeelConsoleAccountSeeder.class);

    public KeelConsoleAccountSeeder(JdbcTemplate jdbcTemplate, PasswordHasher passwordHasher,
                                     MembershipRepository membershipRepository,
                                     @Value("${KEEL_CONSOLE_USERNAME:}") String username,
                                     @Value("${KEEL_CONSOLE_PASSWORD:}") String password) {
        String account = username == null ? "" : username.trim();
        if (account.isEmpty()) {
            log.warn("KEEL_CONSOLE_USERNAME 未配置，跳过控制台账号初始化");
            return;
        }
        String raw = password == null ? "" : password.trim();
        String passwordHash = raw.isEmpty() ? null : passwordHasher.hash(raw);
        Long userId = findUserId(jdbcTemplate, account);
        if (userId == null) {
            jdbcTemplate.update("""
                            INSERT INTO auth_users(username, password_hash, platform_role, session_version, status, created_at)
                            VALUES (?, ?, 'ADMIN', 0, 'ACTIVE', now())
                            """,
                    account, passwordHash);
            userId = findUserId(jdbcTemplate, account);
            if (passwordHash == null) {
                log.warn("KEEL_CONSOLE_PASSWORD 未配置，已创建控制台账号但还不能用密码登录");
            }
        } else if (passwordHash != null) {
            jdbcTemplate.update("""
                            UPDATE auth_users
                            SET password_hash = ?, platform_role = 'ADMIN', status = 'ACTIVE'
                            WHERE id = ?
                            """,
                    passwordHash, userId);
        } else {
            jdbcTemplate.update("""
                            UPDATE auth_users
                            SET platform_role = 'ADMIN', status = 'ACTIVE'
                            WHERE id = ?
                            """,
                    userId);
            log.warn("KEEL_CONSOLE_PASSWORD 未配置，保留控制台账号现有口令");
        }
        if (userId != null) {
            membershipRepository.ensureMembership(userId, "keel", "ADMIN");
        }
    }

    private static Long findUserId(JdbcTemplate jdbcTemplate, String username) {
        List<Long> ids = jdbcTemplate.queryForList(
                "SELECT id FROM auth_users WHERE username = ? LIMIT 1", Long.class, username);
        return ids.isEmpty() ? null : ids.getFirst();
    }
}
