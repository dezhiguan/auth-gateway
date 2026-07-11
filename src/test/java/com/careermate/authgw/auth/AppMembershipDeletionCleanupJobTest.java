package com.careermate.authgw.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.events.EventPublisher;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AppMembershipDeletionCleanupJobTest {

    private MembershipRepository membershipRepository;
    private EventPublisher eventPublisher;
    private AuditLogService auditLogService;
    private AppMembershipDeletionCleanupJob job;

    @BeforeEach
    void setUp() {
        membershipRepository = mock(MembershipRepository.class);
        eventPublisher = mock(EventPublisher.class);
        auditLogService = mock(AuditLogService.class);
        job = new AppMembershipDeletionCleanupJob(membershipRepository, eventPublisher, auditLogService);
    }

    @Test
    void cleanupOne_whenRowGuardWins_auditsAndPublishesAppRemoved() {
        when(membershipRepository.markDeletedIfDue(42L, "careermate")).thenReturn(1);

        job.cleanupOne(42L, "careermate");

        verify(auditLogService).high(eq("app.deletion.purged"), eq(42L), isNull(), eq(Map.of("app", "careermate")));
        verify(eventPublisher).publish(eq("user.app_removed"), eq(Map.of("user_id", 42L, "app", "careermate")));
    }

    @Test
    void cleanupOne_whenRowGuardLoses_doesNothing() {
        when(membershipRepository.markDeletedIfDue(42L, "careermate")).thenReturn(0);

        job.cleanupOne(42L, "careermate");

        verify(auditLogService, never()).high(anyString(), any(), any(), any());
        verify(eventPublisher, never()).publish(anyString(), any());
    }

    @Test
    void run_whenNoneDue_doesNotPublish() {
        when(membershipRepository.findExpiredPendingDeletion(anyInt())).thenReturn(List.of());

        job.run();

        verify(eventPublisher, never()).publish(anyString(), any());
    }

    @Test
    void run_whenOneFails_stillProcessesTheOther() {
        when(membershipRepository.findExpiredPendingDeletion(anyInt())).thenReturn(List.of(
                new AppMembership(1L, "careermate", "USER", "PENDING_DELETION"),
                new AppMembership(2L, "careermate", "USER", "PENDING_DELETION")));
        when(membershipRepository.markDeletedIfDue(1L, "careermate")).thenThrow(new RuntimeException("boom"));
        when(membershipRepository.markDeletedIfDue(2L, "careermate")).thenReturn(1);

        job.run();

        verify(eventPublisher).publish(eq("user.app_removed"), eq(Map.of("user_id", 2L, "app", "careermate")));
    }
}
