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

    /**
     * 申请应用级注销：该 (user, app) membership 进入 30 天冷静期（PENDING_DELETION）。
     * 幂等：已在冷静期则保留首次的计划清理时间，不重置倒计时。
     * @return 计划清理时间；membership 不存在返回 null。
     */
    public java.time.Instant markPendingDeletion(long userId, String app) {
        List<java.time.Instant> rows = jdbcTemplate.query("""
                        UPDATE user_app_membership
                        SET status = 'PENDING_DELETION',
                            pending_deletion_at = COALESCE(pending_deletion_at, now()),
                            deletion_scheduled_at = COALESCE(deletion_scheduled_at, now() + interval '30 days')
                        WHERE user_id = ? AND app = ? AND status IN ('ACTIVE', 'PENDING_DELETION')
                        RETURNING deletion_scheduled_at
                        """,
                (rs, n) -> rs.getTimestamp("deletion_scheduled_at").toInstant(),
                userId, app);
        return rows.stream().findFirst().orElse(null);
    }

    /** 撤销应用级注销：membership 恢复 ACTIVE，清空计划清理时间。返回命中行数。 */
    public int cancelDeletion(long userId, String app) {
        return jdbcTemplate.update("""
                        UPDATE user_app_membership
                        SET status = 'ACTIVE', pending_deletion_at = NULL, deletion_scheduled_at = NULL
                        WHERE user_id = ? AND app = ? AND status = 'PENDING_DELETION'
                        """,
                userId, app);
    }

    /** 到期清理扫描：返回 PENDING_DELETION 且已到期的 (user, app)。 */
    public List<AppMembership> findExpiredPendingDeletion(int limit) {
        return jdbcTemplate.query("""
                        SELECT user_id, app, role, status
                        FROM user_app_membership
                        WHERE status = 'PENDING_DELETION' AND deletion_scheduled_at <= now()
                        ORDER BY deletion_scheduled_at
                        LIMIT ?
                        """,
                (rs, n) -> mapRow(rs),
                limit);
    }

    /**
     * 行级锁守卫地将到期 membership 置为 DELETED。并发副本中仅命中 1 行的那个返回 1，据此发事件、天然幂等。
     * @return 命中行数（1=本副本处理，0=已被其他副本处理或未到期）。
     */
    public int markDeletedIfDue(long userId, String app) {
        return jdbcTemplate.update("""
                        UPDATE user_app_membership
                        SET status = 'DELETED', pending_deletion_at = NULL, deletion_scheduled_at = NULL
                        WHERE user_id = ? AND app = ? AND status = 'PENDING_DELETION' AND deletion_scheduled_at <= now()
                        """,
                userId, app);
    }

    private AppMembership mapRow(ResultSet rs) throws SQLException {
        return new AppMembership(
                rs.getLong("user_id"),
                rs.getString("app"),
                rs.getString("role"),
                rs.getString("status"));
    }
}
