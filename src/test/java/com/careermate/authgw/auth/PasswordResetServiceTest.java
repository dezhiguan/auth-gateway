package com.careermate.authgw.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.crypto.JwksProvider;
import com.careermate.authgw.crypto.JwtSigner;
import com.careermate.authgw.events.EventPublisher;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsCodeStore;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock AuthUserRepository userRepository;
    @Mock MembershipRepository membershipRepository;
    @Mock PasswordHasher passwordHasher;
    @Mock TokenIssuer tokenIssuer;
    @Mock JwtSigner jwtSigner;
    @Mock JwksProvider jwksProvider;
    @Mock JdbcTemplate jdbcTemplate;
    @Mock SmsCodeStore codeStore;
    @Mock SmsAuthRateLimiter smsRateLimiter;
    @Mock MobileSmsAuthProvider smsProvider;
    @Mock EventPublisher eventPublisher;
    @Mock AuditLogService auditLogService;

    private final SmsProperties smsProperties = new SmsProperties();
    private final AuthProperties authProperties = new AuthProperties();

    @Test
    void initReturnsEnumerationSafeResultWhenUserDoesNotExist() {
        when(userRepository.findByAccount("missing")).thenReturn(Optional.empty());

        PasswordResetService.ResetInitResult result = service().init("missing", "13800000000");

        assertThat(result.maskedPhone()).isEqualTo(PasswordResetService.ENUMERATION_SAFE_MASKED_PHONE);
        assertThat(result.ticketRequired()).isTrue();
        verify(smsProvider, never()).sendVerifyCode(any());
    }

    @Test
    void initSendsSmsWhenAccountAndPhoneMatch() {
        String phone = "+8613800000000";
        String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(user(phoneHash)));
        when(smsProvider.sendVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.SendResult(true, "out-1", "req-1", "OK", "ok"));

        PasswordResetService.ResetInitResult result = service().init("13800000000", "13800000000");

        assertThat(result.ticketRequired()).isTrue();
        verify(smsRateLimiter).checkSendAllowed(SmsScene.RESET, phoneHash,
                PhoneSupport.hashIp("password-reset", smsProperties.getPhoneHashPepper()), PhoneSupport.maskPhone(phone));
        verify(smsRateLimiter).storePendingCode(org.mockito.ArgumentMatchers.eq(SmsScene.RESET),
                org.mockito.ArgumentMatchers.eq(phoneHash), anyString(), org.mockito.ArgumentMatchers.eq("out-1"));
        verify(smsRateLimiter).recordSend(SmsScene.RESET, phoneHash,
                PhoneSupport.hashIp("password-reset", smsProperties.getPhoneHashPepper()));
    }

    @Test
    void verifyIssuesResetTicketWhenSmsCodeIsValid() {
        String phone = "+8613800000000";
        String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
        AuthUser user = user(phoneHash);
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(user));
        when(codeStore.getValue("authgw:password-reset:confirm:lock:7")).thenReturn(Optional.empty());
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.RESET, phoneHash)).thenReturn(Optional.of("out-1"));
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, phone, "req-1", "OK", "ok", "PASS"));
        when(jwtSigner.sign(any(com.nimbusds.jwt.JWTClaimsSet.class))).thenReturn("reset-ticket");

        String ticket = service().verify("13800000000", "13800000000", "123456");

        assertThat(ticket).isEqualTo("reset-ticket");
        verify(codeStore).delete("authgw:password-reset:confirm:fail:7");
    }

    @Test
    void verifyRecordsFailureAndLocksAfterInvalidPhone() {
        String phoneHash = PhoneSupport.hashPhone("+8613800000000", smsProperties.getPhoneHashPepper());
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(user(phoneHash)));
        when(codeStore.getValue("authgw:password-reset:confirm:lock:7")).thenReturn(Optional.empty());
        when(codeStore.increment("authgw:password-reset:confirm:fail:7", java.time.Duration.ofMinutes(30))).thenReturn(5L);

        assertThatThrownBy(() -> service().verify("13800000000", "13900000000", "123456"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SMS_CODE_INVALID"));
        verify(codeStore).setValue("authgw:password-reset:confirm:lock:7", "1", java.time.Duration.ofMinutes(30));
    }

    @Test
    void confirmRejectsInvalidResetTicket() {
        assertThatThrownBy(() -> service().confirm("not-a-jwt", "Newpass1", client(), "careermate-api"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("RESET_TICKET_INVALID"));
    }

    private PasswordResetService service() {
        return new PasswordResetService(userRepository, membershipRepository, passwordHasher, tokenIssuer, jwtSigner,
                jwksProvider, jdbcTemplate, smsProperties, codeStore, smsRateLimiter, smsProvider,
                authProperties, eventPublisher, auditLogService);
    }

    private static AuthUser user(String phoneHash) {
        return new AuthUser(7, phoneHash, null, "amy", "pwd", "USER", 2, "ACTIVE");
    }

    private static OAuthClient client() {
        return new OAuthClient("ragforge-admin-backend", "RAGForge", "private_key_jwt", null,
                java.util.Set.of("password"), java.util.Set.of("careermate-api"),
                java.util.Set.of("rag:search"), "ACTIVE");
    }
}
