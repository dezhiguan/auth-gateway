package com.careermate.authgw.auth;

import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsProperties;
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
                    String ragEventSecret) {
        String phoneHash = PhoneSupport.hashPhone("13800000000", smsProperties.getPhoneHashPepper());
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM auth_users WHERE username = ?",
                Integer.class,
                "admin");
        if (count != null && count > 0) {
            jdbcTemplate.update("""
                            UPDATE auth_users
                            SET phone_hash = COALESCE(phone_hash, ?)
                            WHERE username = ?
                            """,
                    phoneHash,
                    "admin");
        } else {
            jdbcTemplate.update("""
                            INSERT INTO auth_users(phone_hash, username, password_hash, platform_role, session_version, status, created_at)
                            VALUES (?, ?, ?, 'ADMIN', 0, 'ACTIVE', now())
                            """,
                    phoneHash,
                    "admin",
                    passwordHasher.hash("Admin123!"));
        }

        // dev admin 同时拥有两个 App 的准入，便于本地联调
        Long adminId = jdbcTemplate.queryForObject(
                "SELECT id FROM auth_users WHERE username = ?",
                Long.class,
                "admin");
        if (adminId != null) {
            membershipRepository.ensureMembership(adminId, "ragforge", "ADMIN");
            membershipRepository.ensureMembership(adminId, "careermate", "USER");
        }

        // dev：启用 ragforge 事件订阅并指向本地 RAG，使用与 RAG 一致的 dev HMAC 密钥，
        // 让"登出/改密 → webhook → 访问令牌吊销"链路在本地可端到端联调。
        // 生产环境保留 V7 迁移里的 INACTIVE 占位行，由部署侧按真实 endpoint/secret 配置。
        int updated = jdbcTemplate.update(
                """
                UPDATE event_subscriptions
                SET endpoint_url = ?, hmac_secret = ?, status = 'ACTIVE'
                WHERE subscriber = 'ragforge'
                """,
                ragEventEndpoint,
                ragEventSecret);
        if (updated == 0) {
            jdbcTemplate.update(
                    """
                    INSERT INTO event_subscriptions(subscriber, event_types, endpoint_url, hmac_key_id, hmac_secret, status)
                    VALUES ('ragforge', '["session.revoked","user.password.changed"]'::jsonb, ?, 'ragforge-hmac-key', ?, 'ACTIVE')
                    ON CONFLICT DO NOTHING
                    """,
                    ragEventEndpoint,
                    ragEventSecret);
        }
    }
}
