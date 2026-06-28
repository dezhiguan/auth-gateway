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
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status
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
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status
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
                        RETURNING id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status
                        """,
                (rs, rowNum) -> mapUser(rs),
                phoneHash);
    }

    public Optional<AuthUser> findByEmailHash(String emailHash) {
        List<AuthUser> users = jdbcTemplate.query("""
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status
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
                        RETURNING id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status
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
                        SELECT id, phone_hash, email_hash, username, password_hash, platform_role, session_version, status
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

    private AuthUser mapUser(ResultSet rs) throws SQLException {
        return new AuthUser(
                rs.getLong("id"),
                rs.getString("phone_hash"),
                rs.getString("email_hash"),
                rs.getString("username"),
                rs.getString("password_hash"),
                rs.getString("platform_role"),
                rs.getLong("session_version"),
                rs.getString("status"));
    }
}
