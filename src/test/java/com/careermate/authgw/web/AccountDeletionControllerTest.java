package com.careermate.authgw.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUser;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AccountDeletionController.class)
class AccountDeletionControllerTest {

    private static final String PEPPER = "test-pepper";
    private static final String PHONE = "13800000001";
    private static final String SMS_CODE = "654321";

    @Autowired MockMvc mockMvc;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean AuthUserRepository userRepository;
    @MockitoBean MobileSmsAuthProvider smsProvider;
    @MockitoBean SmsAuthRateLimiter smsRateLimiter;
    @MockitoBean SmsProperties smsProperties;
    @MockitoBean AuditLogService auditLogService;

    @BeforeEach
    void setUp() {
        when(smsProperties.getPhoneHashPepper()).thenReturn(PEPPER);
    }

    @Test
    void requestDeletionMarksPendingAndReturnsDeletionScheduledAt() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);

        // findById returns user whose phoneHash matches PHONE hashed with PEPPER
        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(5L, phoneHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));

        when(smsRateLimiter.isVerifyBlocked(SmsScene.VERIFICATION, phoneHash)).thenReturn(false);
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.VERIFICATION, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, null, null, null, null, null));

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"%s","smsCode":"%s"}
                                """.formatted(PHONE, SMS_CODE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deletionScheduledAt").isString());

        verify(userRepository).markPendingDeletion(5L);
    }

    @Test
    void requestDeletionReturns400WhenPhoneMismatch() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);

        // Stored phoneHash corresponds to a different phone
        String otherHash = com.careermate.authgw.sms.PhoneSupport.hashPhone("13900000002", PEPPER);
        AuthUser user = new AuthUser(5L, otherHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"%s","smsCode":"%s"}
                                """.formatted(PHONE, SMS_CODE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("PHONE_MISMATCH"));
    }

    @Test
    void requestDeletionReturns401WhenSmsCodeInvalid() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);

        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(5L, phoneHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));

        when(smsRateLimiter.isVerifyBlocked(SmsScene.VERIFICATION, phoneHash)).thenReturn(false);
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.VERIFICATION, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(false, null, null, null, null, null));

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"%s","smsCode":"000000"}
                                """.formatted(PHONE)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SMS_CODE_INVALID"));
    }

    @Test
    void cancelDeletionRestoresActiveStatusViaPhoneAndSms() throws Exception {
        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(6L, phoneHash, null, "bob", null, "USER", 1L, "PENDING_DELETION", null);
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(user));

        when(smsRateLimiter.isVerifyBlocked(SmsScene.VERIFICATION, phoneHash)).thenReturn(false);
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.VERIFICATION, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, null, null, null, null, null));

        mockMvc.perform(delete("/auth/users/me/deletion-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"%s","smsCode":"%s"}
                                """.formatted(PHONE, SMS_CODE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        verify(userRepository).cancelDeletion(6L);
    }

    @Test
    void cancelDeletionReturns400WhenAccountNotPendingDeletion() throws Exception {
        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(6L, phoneHash, null, "bob", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(user));

        mockMvc.perform(delete("/auth/users/me/deletion-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"%s","smsCode":"%s"}
                                """.formatted(PHONE, SMS_CODE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("NOT_PENDING_DELETION"));
    }

    @Test
    void cancelDeletionReturns404WhenUserNotFound() throws Exception {
        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        when(userRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.empty());

        mockMvc.perform(delete("/auth/users/me/deletion-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"%s","smsCode":"%s"}
                                """.formatted(PHONE, SMS_CODE)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("USER_NOT_FOUND"));
    }
}
