package com.careermate.authgw.auth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.events.EventPublisher;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 账号注销冷静期到期后的数据清理：扫描 auth_users 中 PENDING_DELETION 且 deletion_scheduled_at 到期的账号，
 * 匿名化其个人信息（PIPL 合规），并发布 user.deleted 事件通知下游应用（rag-forge）清理各自的数据。
 *
 * <p>2 副本部署下无需 ShedLock：匿名化 UPDATE 带 status='PENDING_DELETION' 守卫，行级锁使并发副本中
 * 仅有一个 UPDATE 命中 1 行，据此决定是否发事件，天然幂等、不会重复发事件。
 */
@Component
public class AccountDeletionCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(AccountDeletionCleanupJob.class);

    private final JdbcTemplate jdbcTemplate;
    private final EventPublisher eventPublisher;
    private final AuditLogService auditLogService;

    public AccountDeletionCleanupJob(
            JdbcTemplate jdbcTemplate, EventPublisher eventPublisher, AuditLogService auditLogService) {
        this.jdbcTemplate = jdbcTemplate;
        this.eventPublisher = eventPublisher;
        this.auditLogService = auditLogService;
    }

    /** 每天凌晨 2 点执行。 */
    @Scheduled(cron = "${auth.account-deletion.cleanup-cron:0 0 2 * * *}")
    public void run() {
        List<Long> dueIds = jdbcTemplate.queryForList("""
                SELECT id FROM auth_users
                WHERE status = 'PENDING_DELETION' AND deletion_scheduled_at <= now()
                """, Long.class);
        if (dueIds.isEmpty()) {
            return;
        }
        log.info("[AccountDeletion] {} account(s) due for cleanup", dueIds.size());
        for (Long userId : dueIds) {
            try {
                cleanupOne(userId);
            } catch (RuntimeException ex) {
                log.error("[AccountDeletion] cleanup failed for user {}: {}", userId, ex.getMessage(), ex);
            }
        }
    }

    void cleanupOne(long userId) {
        // 行级锁守卫：并发副本中仅命中 1 行的那个继续匿名化并发事件；命中 0 行说明已被处理，跳过。
        int updated = jdbcTemplate.update("""
                UPDATE auth_users SET
                    phone_hash = NULL,
                    email_hash = NULL,
                    password_hash = NULL,
                    username = 'deleted_user_' || id,
                    status = 'DELETED',
                    pending_deletion_at = NULL,
                    deletion_scheduled_at = NULL
                WHERE id = ? AND status = 'PENDING_DELETION' AND deletion_scheduled_at <= now()
                """, userId);
        if (updated != 1) {
            return;
        }
        // 会话/令牌失效：递增 session_version 使现存 access token 立即作废。
        jdbcTemplate.update("UPDATE auth_users SET session_version = session_version + 1 WHERE id = ?", userId);
        auditLogService.high("account.deletion.purged", userId, null, Map.of());
        // 通知下游应用清理各自的数据（rag-forge: api_keys / org_members / user_profile）。
        eventPublisher.publish("user.deleted", Map.of("user_id", userId));
        log.info("[AccountDeletion] anonymized user {} and published user.deleted", userId);
    }
}
