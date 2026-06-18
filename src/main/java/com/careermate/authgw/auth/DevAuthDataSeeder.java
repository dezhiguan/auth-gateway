package com.careermate.authgw.auth;

import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@Profile("dev")
public class DevAuthDataSeeder {

    public DevAuthDataSeeder(JdbcTemplate jdbcTemplate, PasswordHasher passwordHasher, SmsProperties smsProperties) {
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
            return;
        }
        jdbcTemplate.update("""
                        INSERT INTO auth_users(phone_hash, username, password_hash, platform_role, session_version, status, created_at)
                        VALUES (?, ?, ?, 'ADMIN', 0, 'ACTIVE', now())
                        """,
                phoneHash,
                "admin",
                passwordHasher.hash("Admin123!"));
    }
}
