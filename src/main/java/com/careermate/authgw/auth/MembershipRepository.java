package com.careermate.authgw.auth;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** 应用准入(membership) 数据访问。一行一个 (user, app)。 */
@Repository
public class MembershipRepository {

    private final JdbcTemplate jdbcTemplate;

    public MembershipRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /** 确保 (user, app) 准入存在；已存在则不变（不覆盖既有 role/status）。 */
    public void ensureMembership(long userId, String app, String role) {
        jdbcTemplate.update("""
                        INSERT INTO user_app_membership(user_id, app, role, status, created_at)
                        VALUES (?, ?, ?, 'ACTIVE', now())
                        ON CONFLICT (user_id, app) DO NOTHING
                        """,
                userId, app, role);
    }

    public Optional<AppMembership> find(long userId, String app) {
        List<AppMembership> rows = jdbcTemplate.query("""
                        SELECT user_id, app, role, status
                        FROM user_app_membership
                        WHERE user_id = ? AND app = ?
                        LIMIT 1
                        """,
                (rs, n) -> mapRow(rs),
                userId, app);
        return rows.stream().findFirst();
    }

    public List<AppMembership> listByUser(long userId) {
        return jdbcTemplate.query("""
                        SELECT user_id, app, role, status
                        FROM user_app_membership
                        WHERE user_id = ?
                        ORDER BY app
                        """,
                (rs, n) -> mapRow(rs),
                userId);
    }

    private AppMembership mapRow(ResultSet rs) throws SQLException {
        return new AppMembership(
                rs.getLong("user_id"),
                rs.getString("app"),
                rs.getString("role"),
                rs.getString("status"));
    }
}
