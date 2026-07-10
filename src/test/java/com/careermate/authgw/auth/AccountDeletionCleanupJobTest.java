package com.careermate.authgw.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.events.EventPublisher;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class AccountDeletionCleanupJobTest {

    private JdbcTemplate jdbcTemplate;
    private EventPublisher eventPublisher;
    private AuditLogService auditLogService;
    private AccountDeletionCleanupJob job;

    @BeforeEach
    void setUp() {
        jdbcTemplate = mock(JdbcTemplate.class);
        eventPublisher = mock(EventPublisher.class);
        auditLogService = mock(AuditLogService.class);
        job = new AccountDeletionCleanupJob(jdbcTemplate, eventPublisher, auditLogService);
    }

    @Test
    void cleanupOne_whenRowGuardWins_anonymizesBumpsSessionAndPublishes() {
        when(jdbcTemplate.update(contains("status = 'DELETED'"), eq(42L))).thenReturn(1);

        job.cleanupOne(42L);

        verify(jdbcTemplate).update(contains("session_version = session_version + 1"), eq(42L));
        verify(auditLogService).high(eq("account.deletion.purged"), eq(42L), isNull(), any());
        verify(eventPublisher).publish(eq("user.deleted"), any());
    }

    @Test
    void cleanupOne_whenRowGuardLoses_doesNothingFurther() {
        // 另一个副本已处理：匿名化 UPDATE 命中 0 行 → 不发事件、不递增 session_version、不写审计。
        when(jdbcTemplate.update(contains("status = 'DELETED'"), eq(42L))).thenReturn(0);

        job.cleanupOne(42L);

        verify(jdbcTemplate, never()).update(contains("session_version"), eq(42L));
        verify(auditLogService, never()).high(anyString(), any(), any(), any());
        verify(eventPublisher, never()).publish(anyString(), any());
    }

    @Test
    void run_whenNoDueAccounts_doesNotPublish() {
        when(jdbcTemplate.queryForList(anyString(), eq(Long.class))).thenReturn(List.of());

        job.run();

        verify(eventPublisher, never()).publish(anyString(), any());
    }

    @Test
    void run_whenOneAccountFails_stillProcessesTheOther() {
        when(jdbcTemplate.queryForList(anyString(), eq(Long.class))).thenReturn(List.of(1L, 2L));
        when(jdbcTemplate.update(contains("status = 'DELETED'"), eq(1L)))
                .thenThrow(new RuntimeException("boom"));
        when(jdbcTemplate.update(contains("status = 'DELETED'"), eq(2L))).thenReturn(1);

        job.run();

        // user 1 抛异常被吞，user 2 仍完成清理并发事件。
        verify(eventPublisher).publish(eq("user.deleted"), any());
        verify(jdbcTemplate).update(contains("session_version = session_version + 1"), eq(2L));
    }
}
