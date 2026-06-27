package com.careermate.authgw.auth;

import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsProperties;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("dev")
public class DevAuthDataSeeder {

    public DevAuthDataSeeder(
            JdbcTemplate jdbcTemplate,
            PasswordHasher passwordHasher,
            SmsProperties smsProperties,
            MembershipRepository membershipRepository,
            @Value("${dev.ragforge-event-endpoint:http://localhost:8080/api/v1/events/session-revoked}")
                    String ragEventEndpoint,
            @Value("${dev.ragforge-event-hmac-secret:dev-secret-must-match-authgw}")
                    String ragEventSecret,
            @Value("${dev.careermate-event-endpoint:http://localhost:8081/api/v1/events/session-revoked}")
                    String careermateEventEndpoint,
            @Value("${dev.careermate-event-hmac-secret:dev-secret-must-match-authgw}")
                    String careermateEventSecret) {
        String phoneHash = PhoneSupport.hashPhone("13800000000", smsProperties.getPhoneHashPepper());
        String passwordHash = passwordHasher.hash("Admin123!");
        Long adminId = findUserId(jdbcTemplate, "SELECT id FROM auth_users WHERE username = ? LIMIT 1", "admin");
        if (adminId != null) {
            jdbcTemplate.update("""
                            UPDATE auth_users
                            SET phone_hash = CASE
                                    WHEN phone_hash IS NULL
                                        AND NOT EXISTS (
                                            SELECT 1 FROM auth_users other_user
                                            WHERE other_user.phone_hash = ? AND other_user.id <> auth_users.id
                                        )
                                    THEN ?
                                    ELSE phone_hash
                                END,
                                password_hash = COALESCE(password_hash, ?),
                                tenant_id = CASE WHEN tenant_id IS NULL OR tenant_id = '' THEN ? ELSE tenant_id END,
                                platform_role = 'ADMIN',
                                status = 'ACTIVE'
                            WHERE id = ?
                            """,
                    phoneHash,
                    phoneHash,
                    passwordHash,
                    "tn_dev_admin",
                    adminId);
        } else {
            Long phoneUserId = findUserId(jdbcTemplate, "SELECT id FROM auth_users WHERE phone_hash = ? LIMIT 1", phoneHash);
            if (phoneUserId != null) {
                jdbcTemplate.update("""
                                UPDATE auth_users
                                SET username = ?,
                                    password_hash = COALESCE(password_hash, ?),
                                    tenant_id = CASE WHEN tenant_id IS NULL OR tenant_id = '' THEN ? ELSE tenant_id END,
                                    platform_role = 'ADMIN',
                                    status = 'ACTIVE'
                                WHERE id = ?
                                """,
                        "admin",
                        passwordHash,
                        "tn_dev_admin",
                        phoneUserId);
                adminId = phoneUserId;
            } else {
                jdbcTemplate.update("""
                                INSERT INTO auth_users(phone_hash, username, password_hash, tenant_id, platform_role, session_version, status, created_at)
                                VALUES (?, ?, ?, ?, 'ADMIN', 0, 'ACTIVE', now())
                                """,
                        phoneHash,
                        "admin",
                        passwordHash,
                        "tn_dev_admin");
                adminId = findUserId(jdbcTemplate, "SELECT id FROM auth_users WHERE username = ? LIMIT 1", "admin");
            }
        }

        // dev admin 同时拥有两个 App 的准入，便于本地联调
        if (adminId != null) {
            membershipRepository.ensureMembership(adminId, "ragforge", "ADMIN");
            membershipRepository.ensureMembership(adminId, "careermate", "USER");
        }

        // dev：启用 App 事件订阅并指向本地服务，使用与下游一致的 dev HMAC 密钥，
        // 让"登出/改密 → webhook → 访问令牌吊销"链路在本地可端到端联调。
        // 生产环境保留 V7 迁移里的 INACTIVE 占位行，由部署侧按真实 endpoint/secret 配置。
        upsertEventSubscription(jdbcTemplate, "ragforge", ragEventEndpoint, ragEventSecret);
        upsertEventSubscription(jdbcTemplate, "careermate", careermateEventEndpoint, careermateEventSecret);
    }

    private static void upsertEventSubscription(
            JdbcTemplate jdbcTemplate,
            String subscriber,
            String endpoint,
            String secret) {
        int updated = jdbcTemplate.update(
                """
                UPDATE event_subscriptions
                SET endpoint_url = ?, hmac_secret = ?, status = 'ACTIVE'
                WHERE subscriber = ?
                """,
                endpoint,
                secret,
                subscriber);
        if (updated == 0) {
            jdbcTemplate.update(
                    """
                    INSERT INTO event_subscriptions(subscriber, event_types, endpoint_url, hmac_key_id, hmac_secret, status)
                    VALUES (?, '["session.revoked","user.password.changed"]'::jsonb, ?, ?, ?, 'ACTIVE')
                    ON CONFLICT DO NOTHING
                    """,
                    subscriber,
                    endpoint,
                    subscriber + "-hmac-key",
                    secret);
        }
    }

    private static Long findUserId(JdbcTemplate jdbcTemplate, String sql, String value) {
        List<Long> ids = jdbcTemplate.queryForList(sql, Long.class, value);
        return ids.isEmpty() ? null : ids.getFirst();
    }
}
