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
