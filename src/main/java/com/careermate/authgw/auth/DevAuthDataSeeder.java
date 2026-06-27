package com.careermate.authgw.auth;

import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsProperties;
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
            MembershipRepository membershipRepository) {
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
    }
}
