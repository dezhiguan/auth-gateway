package com.careermate.authgw.auth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.events.EventPublisher;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 应用级注销冷静期到期后的清理：扫描 user_app_membership 中 PENDING_DELETION 且到期的 (user, app)，
 * 置为 DELETED，并发布 {@code user.app_removed} 事件通知对应下游应用清理其数据（不影响其他 App / 共享身份）。
 *
 * <p>多副本安全：markDeletedIfDue 带 {@code WHERE status='PENDING_DELETION' AND deletion_scheduled_at<=now()}
 * 行级锁守卫，并发副本中仅 1 个 UPDATE 命中 1 行，据此决定发事件，天然幂等、不重复发。</p>
 */
@Component
public class AppMembershipDeletionCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(AppMembershipDeletionCleanupJob.class);
    private static final int BATCH = 500;

    private final MembershipRepository membershipRepository;
    private final EventPublisher eventPublisher;
    private final AuditLogService auditLogService;

    public AppMembershipDeletionCleanupJob(
            MembershipRepository membershipRepository,
            EventPublisher eventPublisher,
            AuditLogService auditLogService) {
        this.membershipRepository = membershipRepository;
        this.eventPublisher = eventPublisher;
        this.auditLogService = auditLogService;
    }

    /** 每天凌晨 2:10 执行（与账号级清理错开）。 */
    @Scheduled(cron = "${auth.app-deletion.cleanup-cron:0 10 2 * * *}")
    public void run() {
        List<AppMembership> due = membershipRepository.findExpiredPendingDeletion(BATCH);
        if (due.isEmpty()) {
            return;
        }
        log.info("[AppDeletion] {} membership(s) due for cleanup", due.size());
        for (AppMembership m : due) {
            try {
                cleanupOne(m.userId(), m.app());
            } catch (RuntimeException ex) {
                log.error("[AppDeletion] cleanup failed for user {} app {}: {}", m.userId(), m.app(), ex.getMessage(), ex);
            }
        }
    }

    void cleanupOne(long userId, String app) {
        int updated = membershipRepository.markDeletedIfDue(userId, app);
        if (updated != 1) {
            return; // 已被其他副本处理或未到期
        }
        auditLogService.high("app.deletion.purged", userId, null, Map.of("app", app));
        // 通知对应下游应用清理其数据（如 careermate: user 主记录匿名化 + 简历/对话等）。
        eventPublisher.publish("user.app_removed", Map.of("user_id", userId, "app", app));
        log.info("[AppDeletion] removed membership user {} app {} and published user.app_removed", userId, app);
    }
}
