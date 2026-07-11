package com.careermate.authgw.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AppMembership;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUser;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.auth.MembershipRepository;
import com.careermate.authgw.auth.TokenService;
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
    @MockitoBean MembershipRepository membershipRepository;
    @MockitoBean TokenService tokenService;
    @MockitoBean MobileSmsAuthProvider smsProvider;
    @MockitoBean SmsAuthRateLimiter smsRateLimiter;
    @MockitoBean SmsProperties smsProperties;
    @MockitoBean AuditLogService auditLogService;

    @BeforeEach
    void setUp() {
        when(smsProperties.getPhoneHashPepper()).thenReturn(PEPPER);
    }

    @Test
    void requestDeletionMarksRagforgeMembershipPendingAndRevokesSessions() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);

        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(5L, phoneHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));
        when(smsRateLimiter.isVerifyBlocked(SmsScene.VERIFICATION, phoneHash)).thenReturn(false);
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.VERIFICATION, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, null, null, null, null, null));
        when(membershipRepository.markPendingDeletion(5L, "ragforge")).thenReturn(java.time.Instant.parse("2026-08-10T00:00:00Z"));

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"%s\",\"smsCode\":\"%s\"}".formatted(PHONE, SMS_CODE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deletionScheduledAt").isString());

        verify(membershipRepository).markPendingDeletion(5L, "ragforge");
        verify(tokenService).revokeUserSessionsForAudience(5L, "ragforge-admin-api", "ragforge-account-deletion");
    }

    @Test
    void requestDeletionReturns404WhenNoRagforgeMembership() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(5L, phoneHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));
        when(smsRateLimiter.isVerifyBlocked(SmsScene.VERIFICATION, phoneHash)).thenReturn(false);
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.VERIFICATION, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any())).thenReturn(new MobileSmsAuthProvider.VerifyResult(true, null, null, null, null, null));
        when(membershipRepository.markPendingDeletion(5L, "ragforge")).thenReturn(null);

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"%s\",\"smsCode\":\"%s\"}".formatted(PHONE, SMS_CODE)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("APP_MEMBERSHIP_NOT_FOUND"));
    }

    @Test
    void requestDeletionReturns400WhenPhoneMismatch() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        String otherHash = com.careermate.authgw.sms.PhoneSupport.hashPhone("13900000002", PEPPER);
        AuthUser user = new AuthUser(5L, otherHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"%s\",\"smsCode\":\"%s\"}".formatted(PHONE, SMS_CODE)))
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
                        .content("{\"phone\":\"%s\",\"smsCode\":\"000000\"}".formatted(PHONE)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SMS_CODE_INVALID"));
    }

    @Test
    void cancelDeletionRestoresActiveViaBearerOnly() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:6").claim("user_id", 6L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        when(membershipRepository.cancelDeletion(6L, "ragforge")).thenReturn(1);

        mockMvc.perform(delete("/auth/users/me/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        verify(membershipRepository).cancelDeletion(6L, "ragforge");
    }

    @Test
    void cancelDeletionReturns400WhenNotPending() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:6").claim("user_id", 6L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        when(membershipRepository.cancelDeletion(6L, "ragforge")).thenReturn(0);

        mockMvc.perform(delete("/auth/users/me/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("NOT_PENDING_DELETION"));
    }

    @Test
    void deletionStatusReturnsPendingInfo() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:6").claim("user_id", 6L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        when(membershipRepository.find(6L, "ragforge"))
                .thenReturn(Optional.of(new AppMembership(6L, "ragforge", "USER", "PENDING_DELETION")));
        when(membershipRepository.getDeletionScheduledAt(6L, "ragforge"))
                .thenReturn(java.time.Instant.parse("2026-08-10T00:00:00Z"));

        mockMvc.perform(get("/auth/users/me/deletion-status").header("Authorization", "Bearer tok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pendingDeletion").value(true))
                .andExpect(jsonPath("$.deletionScheduledAt").value("2026-08-10T00:00:00Z"));
    }

    @Test
    void requestDeletionWithMalformedPhoneReturnsFriendly400() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        AuthUser user = new AuthUser(5L, "hash", null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"abc\",\"smsCode\":\"654321\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("PHONE_FORMAT_INVALID"));
    }

    @Test
    void requestDeletionWithBlankSmsCodeReturns400() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        String phoneHash = com.careermate.authgw.sms.PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(5L, phoneHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));

        mockMvc.perform(post("/auth/users/me/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"%s\",\"smsCode\":\"\"}".formatted(PHONE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("SMS_CODE_REQUIRED"));
    }
}
