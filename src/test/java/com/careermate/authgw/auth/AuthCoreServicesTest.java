package com.careermate.authgw.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.events.EventPublisher;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsCodeStore;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class AuthCoreServicesTest {

    @Mock AuthUserRepository userRepository;
    @Mock MembershipRepository membershipRepository;
    @Mock PasswordHasher passwordHasher;
    @Mock TokenIssuer tokenIssuer;
    @Mock SmsCodeStore codeStore;
    @Mock SmsAuthRateLimiter smsRateLimiter;
    @Mock MobileSmsAuthProvider smsProvider;
    @Mock JdbcTemplate jdbcTemplate;
    @Mock AuditLogService auditLogService;
    @Mock EventPublisher eventPublisher;

    private final SmsProperties smsProperties = new SmsProperties();

    @Test
    void loginPasswordIssuesTokensForActiveUserWithRagforgeMembership() {
        AuthUser user = user(7, "hash", "alice", "pwd-hash", "ADMIN", 2, "ACTIVE");
        OAuthClient client = client();
        TokenPair pair = new TokenPair("access", "refresh", "Bearer", 900);
        when(codeStore.getValue("authgw:login:password:lock:alice")).thenReturn(Optional.empty());
        when(userRepository.findByAccount("alice")).thenReturn(Optional.of(user));
        when(passwordHasher.matches("secret", "pwd-hash")).thenReturn(true);
        when(membershipRepository.find(7, "ragforge")).thenReturn(Optional.of(new AppMembership(7, "ragforge", "USER", "ACTIVE")));
        when(tokenIssuer.issueUserTokens(user, client, "ragforge-admin-api")).thenReturn(pair);

        TokenPair result = loginService().loginPassword("alice", "secret", "ragforge-admin-api", client);

        assertThat(result).isSameAs(pair);
        verify(codeStore).delete("authgw:login:password:fail:alice");
        verify(auditLogService).info("login.password.success", 7L, "ragforge-admin-backend", Map.of("target_aud", "ragforge-admin-api"));
    }

    @Test
    void loginPasswordLocksAfterRepeatedFailures() {
        when(codeStore.getValue("authgw:login:password:lock:missing")).thenReturn(Optional.empty());
        when(userRepository.findByAccount("missing")).thenReturn(Optional.empty());
        when(codeStore.increment("authgw:login:password:fail:missing", java.time.Duration.ofMinutes(5))).thenReturn(5L);

        assertThatThrownBy(() -> loginService().loginPassword("missing", "bad", "careermate-api", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> {
                    assertThat(ex.status()).isEqualTo(423);
                    assertThat(ex.code()).isEqualTo("CAPTCHA_REQUIRED");
                });
        verify(codeStore).setValue("authgw:login:password:lock:missing", "1", java.time.Duration.ofMinutes(30));
    }

    @Test
    void loginPasswordRejectsInactiveUser() {
        AuthUser user = user(7, "hash", "alice", "pwd-hash", "ADMIN", 2, "DISABLED");
        when(codeStore.getValue("authgw:login:password:lock:alice")).thenReturn(Optional.empty());
        when(userRepository.findByAccount("alice")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> loginService().loginPassword("alice", "secret", "careermate-api", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("BAD_CREDENTIALS"));
        verify(tokenIssuer, never()).issueUserTokens(any(), any(), anyString());
    }

    @Test
    void loginPasswordRejectsRagforgeWhenMembershipMissing() {
        AuthUser user = user(7, "hash", "alice", "pwd-hash", "USER", 2, "ACTIVE");
        when(codeStore.getValue("authgw:login:password:lock:alice")).thenReturn(Optional.empty());
        when(userRepository.findByAccount("alice")).thenReturn(Optional.of(user));
        when(passwordHasher.matches("secret", "pwd-hash")).thenReturn(true);
        when(membershipRepository.find(7, "ragforge")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> loginService().loginPassword("alice", "secret", "ragforge-admin-api", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("RAGFORGE_ACCESS_DENIED"));
    }

    @Test
    void loginMobileCreatesUserWhenPhoneDoesNotExist() {
        String phone = "+8613800000000";
        String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
        AuthUser user = user(9, phoneHash, null, null, "USER", 0, "ACTIVE");
        OAuthClient client = client();
        TokenPair pair = new TokenPair("access", "refresh", "Bearer", 900);
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.LOGIN, phoneHash)).thenReturn(Optional.of("out-1"));
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, phone, "req-1", "OK", "ok", "PASS"));
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.empty());
        when(userRepository.createMobileUser(phoneHash)).thenReturn(user);
        when(tokenIssuer.issueUserTokens(user, client, "careermate-api")).thenReturn(pair);

        assertThat(loginService().loginMobile("13800000000", "123456", "careermate-api", client)).isSameAs(pair);
        verify(smsRateLimiter).clearPendingCode(SmsScene.LOGIN, phoneHash);
    }

    @Test
    void loginMobileRejectsInvalidSmsCode() {
        String phone = "+8613800000000";
        String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.LOGIN, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(false, phone, "req-1", "BAD", "bad", "FAIL"));

        assertThatThrownBy(() -> loginService().loginMobile("13800000000", "000000", "careermate-api", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SMS_CODE_INVALID"));
        verify(userRepository, never()).findByPhoneHash(anyString());
    }

    @Test
    void loginMobileRejectsInactiveUser() {
        String phone = "+8613800000000";
        String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
        AuthUser disabled = user(9, phoneHash, null, null, "USER", 0, "DISABLED");
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.LOGIN, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, phone, "req-1", "OK", "ok", "PASS"));
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(disabled));

        assertThatThrownBy(() -> loginService().loginMobile("13800000000", "123456", "careermate-api", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("USER_NOT_FOUND"));
    }

    @Test
    void registerCreatesFullUserAndMembershipAfterSmsVerification() {
        String phone = "+8613800000000";
        String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
        AuthUser created = user(11, phoneHash, "amy", "hash", "USER", 0, "ACTIVE");
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.REGISTER, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, phone, "req-1", "OK", "ok", "PASS"));
        when(passwordHasher.hash("Passw0rd")).thenReturn("pwd-hash");
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.empty());
        when(userRepository.findByAccount("amy")).thenReturn(Optional.empty());
        when(userRepository.findByEmailHash(anyString())).thenReturn(Optional.empty());
        when(userRepository.createFullUser(anyString(), anyString(), anyString(), anyString())).thenReturn(created);

        RegistrationService.RegisterResult result = registrationService()
                .register("13800000000", "123456", " amy ", "amy@example.com", "Passw0rd", "ragforge");

        assertThat(result.userId()).isEqualTo(11);
        assertThat(result.linked()).isFalse();
        verify(membershipRepository).ensureMembership(11, "ragforge", "USER");
    }

    @Test
    void registerRejectsWeakPassword() {
        String phoneHash = PhoneSupport.hashPhone("+8613800000000", smsProperties.getPhoneHashPepper());
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.REGISTER, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, "+8613800000000", "req-1", "OK", "ok", "PASS"));

        assertThatThrownBy(() -> registrationService().register("13800000000", "123456", "amy", null, "password", "ragforge"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("PASSWORD_WEAK"));
    }

    @Test
    void registerEnrichesExistingPhoneWithoutOverwritingExistingFields() {
        String phone = "+8613800000000";
        String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
        AuthUser existing = new AuthUser(15, phoneHash, "existing-email", "existing_user", null, "USER", 1, "ACTIVE");
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.REGISTER, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, phone, "req-1", "OK", "ok", "PASS"));
        when(passwordHasher.hash("Passw0rd")).thenReturn("pwd-hash");
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(existing));

        RegistrationService.RegisterResult result = registrationService()
                .register("13800000000", "123456", "new_user", "new@example.com", "Passw0rd", "careermate");

        assertThat(result.userId()).isEqualTo(15);
        assertThat(result.linked()).isTrue();
        verify(userRepository).enrich(15, null, null, "pwd-hash");
        verify(membershipRepository).ensureMembership(15, "careermate", "USER");
    }

    @Test
    void setPasswordRequiresOldPasswordWhenPasswordAlreadyExists() {
        when(userRepository.findById(3)).thenReturn(Optional.of(user(3, "ph", "amy", "old-hash", "USER", 0, "ACTIVE")));
        when(passwordHasher.matches("wrong", "old-hash")).thenReturn(false);

        assertThatThrownBy(() -> credentialService().setPassword(3, "wrong", "Newpass1"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("OLD_PASSWORD_INVALID"));
    }

    @Test
    void bindEmailRejectsEmailOwnedByAnotherUser() {
        AuthUser user = user(3, "ph", "amy", "pwd-hash", "USER", 0, "ACTIVE");
        AuthUser other = user(4, "ph2", "bob", "pwd-hash", "USER", 0, "ACTIVE");
        when(userRepository.findById(3)).thenReturn(Optional.of(user));
        when(passwordHasher.matches("secret", "pwd-hash")).thenReturn(true);
        when(userRepository.findByEmailHash(anyString())).thenReturn(Optional.of(other));

        assertThatThrownBy(() -> credentialService().bindEmail(3, "amy@example.com", "secret"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("EMAIL_TAKEN"));
    }

    @Test
    void setUsernameTrimsAndUpdatesAvailableUsername() {
        when(userRepository.findByAccount("amy_01")).thenReturn(Optional.empty());

        credentialService().setUsername(3, " amy_01 ");

        verify(userRepository).updateUsername(3, "amy_01");
    }

    private LoginService loginService() {
        return new LoginService(userRepository, membershipRepository, passwordHasher, tokenIssuer, codeStore,
                smsRateLimiter, smsProvider, smsProperties, jdbcTemplate, auditLogService);
    }

    private RegistrationService registrationService() {
        return new RegistrationService(userRepository, membershipRepository, passwordHasher, smsProvider,
                smsRateLimiter, smsProperties, auditLogService);
    }

    private CredentialService credentialService() {
        return new CredentialService(userRepository, passwordHasher, jdbcTemplate, eventPublisher, auditLogService, smsProperties);
    }

    private static AuthUser user(long id, String phoneHash, String username, String passwordHash, String role, long sessionVersion, String status) {
        return new AuthUser(id, phoneHash, null, username, passwordHash, role, sessionVersion, status);
    }

    private static OAuthClient client() {
        return new OAuthClient("ragforge-admin-backend", "RAGForge", "private_key_jwt", null,
                Set.of("password", "refresh_token"), Set.of("careermate-api", "ragforge-admin-api"),
                Set.of("rag:admin:read", "rag:admin:write", "rag:search"), "ACTIVE");
    }
}
