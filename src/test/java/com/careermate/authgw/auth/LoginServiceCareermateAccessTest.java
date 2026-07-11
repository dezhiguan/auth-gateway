package com.careermate.authgw.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsCodeStore;
import com.careermate.authgw.sms.SmsProperties;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

/** enforceCareermateAccess：只在 careermate membership 已 DELETED 时拒登，其余放行。 */
class LoginServiceCareermateAccessTest {

    private MembershipRepository membershipRepository;
    private LoginService loginService;

    private AuthUser user(long id) {
        return new AuthUser(id, "ph", null, "u", "hash", "USER", 1L, "ACTIVE", null);
    }

    @BeforeEach
    void setUp() {
        membershipRepository = mock(MembershipRepository.class);
        loginService = new LoginService(
                mock(AuthUserRepository.class), membershipRepository, mock(PasswordHasher.class),
                mock(TokenIssuer.class), mock(SmsCodeStore.class), mock(SmsAuthRateLimiter.class),
                mock(MobileSmsAuthProvider.class), mock(SmsProperties.class), mock(JdbcTemplate.class),
                mock(AuditLogService.class), mock(CaptchaService.class));
    }

    @Test
    void nonCareermateAud_passes() {
        assertDoesNotThrow(() -> loginService.enforceCareermateAccess("ragforge-admin-api", user(1L)));
    }

    @Test
    void noMembership_passes() {
        when(membershipRepository.find(1L, "careermate")).thenReturn(Optional.empty());
        assertDoesNotThrow(() -> loginService.enforceCareermateAccess("careermate-api", user(1L)));
    }

    @Test
    void activeMembership_passes() {
        when(membershipRepository.find(1L, "careermate"))
                .thenReturn(Optional.of(new AppMembership(1L, "careermate", "USER", "ACTIVE")));
        assertDoesNotThrow(() -> loginService.enforceCareermateAccess("careermate-api", user(1L)));
    }

    @Test
    void pendingDeletionMembership_passes_toAllowInterstitialRestore() {
        when(membershipRepository.find(1L, "careermate"))
                .thenReturn(Optional.of(new AppMembership(1L, "careermate", "USER", "PENDING_DELETION")));
        assertDoesNotThrow(() -> loginService.enforceCareermateAccess("careermate-api", user(1L)));
    }

    @Test
    void deletedMembership_throws403() {
        when(membershipRepository.find(1L, "careermate"))
                .thenReturn(Optional.of(new AppMembership(1L, "careermate", "USER", "DELETED")));
        AuthException ex = assertThrows(AuthException.class,
                () -> loginService.enforceCareermateAccess("careermate-api", user(1L)));
        assertEquals(403, ex.status());
        assertEquals("CAREERMATE_ACCESS_REVOKED", ex.code());
    }
}
