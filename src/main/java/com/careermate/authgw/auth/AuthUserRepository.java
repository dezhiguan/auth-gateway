package com.careermate.authgw.auth;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AuthUserRepository {

    private final JdbcTemplate jdbcTemplate;

    public AuthUserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<AuthUser> findByAccount(String account) {
        List<AuthUser> users = jdbcTemplate.query("""
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status, terms_version
                        FROM auth_users
                        WHERE username = ?
                        LIMIT 1
                        """,
                (rs, rowNum) -> mapUser(rs),
                account);
        return users.stream().findFirst();
    }

    public Optional<AuthUser> findByPhoneHash(String phoneHash) {
        List<AuthUser> users = jdbcTemplate.query("""
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status, terms_version
                        FROM auth_users
                        WHERE phone_hash = ?
                        LIMIT 1
                        """,
                (rs, rowNum) -> mapUser(rs),
                phoneHash);
        return users.stream().findFirst();
    }

    public AuthUser createMobileUser(String phoneHash) {
        return jdbcTemplate.queryForObject("""
                        INSERT INTO auth_users(phone_hash, platform_role, session_version, status, created_at)
                        VALUES (?, 'USER', 0, 'ACTIVE', now())
                        RETURNING id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status, terms_version
                        """,
                (rs, rowNum) -> mapUser(rs),
                phoneHash);
    }

    public Optional<AuthUser> findByEmailHash(String emailHash) {
        List<AuthUser> users = jdbcTemplate.query("""
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status, terms_version
                        FROM auth_users
                        WHERE email_hash = ?
                        LIMIT 1
                        """,
                (rs, rowNum) -> mapUser(rs),
                emailHash);
        return users.stream().findFirst();
    }

    /** 全新注册：手机号为关联键，可同时带 email/username/password。 */
    public AuthUser createFullUser(String phoneHash, String emailHash, String username, String passwordHash) {
        return jdbcTemplate.queryForObject("""
                        INSERT INTO auth_users(phone_hash, email_hash, username, password_hash, platform_role, session_version, status, created_at)
                        VALUES (?, ?, ?, ?, 'USER', 0, 'ACTIVE', now())
                        RETURNING id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status, terms_version
                        """,
                (rs, rowNum) -> mapUser(rs),
                phoneHash, emailHash, username, passwordHash);
    }

    /** 补全：仅填充当前为空的字段，不覆盖已有值。 */
    public void enrich(long id, String emailHash, String username, String passwordHash) {
        jdbcTemplate.update("""
                        UPDATE auth_users
                        SET email_hash = COALESCE(email_hash, ?),
                            username = COALESCE(username, ?),
                            password_hash = COALESCE(password_hash, ?)
                        WHERE id = ?
                        """,
                emailHash, username, passwordHash, id);
    }

    public void updateEmailHash(long id, String emailHash) {
        jdbcTemplate.update("UPDATE auth_users SET email_hash = ? WHERE id = ?", emailHash, id);
    }

    public void updateUsername(long id, String username) {
        jdbcTemplate.update("UPDATE auth_users SET username = ? WHERE id = ?", username, id);
    }

    public Optional<AuthUser> findById(long id) {
        List<AuthUser> users = jdbcTemplate.query("""
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status, terms_version
                        FROM auth_users
                        WHERE id = ?
                        LIMIT 1
                        """,
                (rs, rowNum) -> mapUser(rs),
                id);
        return users.stream().findFirst();
    }

    public void updatePasswordAndIncrementSessionVersion(long id, String passwordHash) {
        jdbcTemplate.update("""
                        UPDATE auth_users
                        SET password_hash = ?, session_version = session_version + 1
                        WHERE id = ?
                        """,
                passwordHash, id);
    }

    /** 记录协议同意：更新已接受协议版本和时间戳。 */
    public void updateTermsAcceptance(long userId, String termsVersion) {
        jdbcTemplate.update("""
                        UPDATE auth_users
                        SET terms_version = ?, terms_accepted_at = now()
                        WHERE id = ?
                        """,
                termsVersion, userId);
    }

    /**
     * 申请注销：进入 30 天冷静期，账号变为 PENDING_DELETION 状态。
     * 幂等：COALESCE 保留已存在的注销时间戳，重复申请不重置倒计时；返回实际生效的计划清理时间。
     */
    public java.time.Instant markPendingDeletion(long userId) {
        return jdbcTemplate.queryForObject("""
                        UPDATE auth_users
                        SET status = 'PENDING_DELETION',
                            pending_deletion_at = COALESCE(pending_deletion_at, now()),
                            deletion_scheduled_at = COALESCE(deletion_scheduled_at, now() + interval '30 days')
                        WHERE id = ?
                        RETURNING deletion_scheduled_at
                        """,
                (rs, rowNum) -> rs.getTimestamp("deletion_scheduled_at").toInstant(),
                userId);
    }

    /** 读取计划清理时间（供设置页展示"X 天后删除"）。 */
    public java.time.Instant getDeletionScheduledAt(long userId) {
        return jdbcTemplate.queryForObject(
                "SELECT deletion_scheduled_at FROM auth_users WHERE id = ?",
                (rs, rowNum) -> {
                    java.sql.Timestamp ts = rs.getTimestamp("deletion_scheduled_at");
                    return ts == null ? null : ts.toInstant();
                },
                userId);
    }

    /** 撤销注销：恢复 ACTIVE 状态，清空注销时间戳。 */
    public void cancelDeletion(long userId) {
        jdbcTemplate.update("""
                        UPDATE auth_users
                        SET status = 'ACTIVE',
                            pending_deletion_at = NULL,
                            deletion_scheduled_at = NULL
                        WHERE id = ?
                        """,
                userId);
    }

    /** 递增 session_version，使该用户所有现存 access token 在下次使用时失效（最多 15 分钟生效）。 */
    public void incrementSessionVersion(long userId) {
        jdbcTemplate.update("""
                        UPDATE auth_users
                        SET session_version = session_version + 1
                        WHERE id = ?
                        """,
                userId);
    }

    private AuthUser mapUser(ResultSet rs) throws SQLException {
        return new AuthUser(
                rs.getLong("id"),
                rs.getString("phone_hash"),
                rs.getString("email_hash"),
                rs.getString("username"),
                rs.getString("password_hash"),
                rs.getString("platform_role"),
                rs.getLong("session_version"),
                rs.getString("status"),
                rs.getString("terms_version"));
    }
}
