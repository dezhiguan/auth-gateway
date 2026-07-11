package com.careermate.authgw.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AppMembership;
import com.careermate.authgw.auth.AuthUser;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.auth.MembershipRepository;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AppDeletionController.class)
class AppDeletionControllerTest {

    private static final String PEPPER = "test-pepper";
    private static final String PHONE = "13800000001";
    private static final String SMS_CODE = "654321";

    @Autowired MockMvc mockMvc;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean AuthUserRepository userRepository;
    @MockitoBean MembershipRepository membershipRepository;
    @MockitoBean MobileSmsAuthProvider smsProvider;
    @MockitoBean SmsAuthRateLimiter smsRateLimiter;
    @MockitoBean SmsProperties smsProperties;
    @MockitoBean AuditLogService auditLogService;

    @BeforeEach
    void setUp() {
        when(smsProperties.getPhoneHashPepper()).thenReturn(PEPPER);
    }

    private void stubAuthAndSms() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        String phoneHash = PhoneSupport.hashPhone(PHONE, PEPPER);
        AuthUser user = new AuthUser(5L, phoneHash, null, "alice", null, "USER", 1L, "ACTIVE", null);
        when(userRepository.findById(5L)).thenReturn(Optional.of(user));
        when(smsRateLimiter.isVerifyBlocked(SmsScene.VERIFICATION, phoneHash)).thenReturn(false);
        when(smsRateLimiter.getPendingProviderOutId(SmsScene.VERIFICATION, phoneHash)).thenReturn(Optional.empty());
        when(smsProvider.checkVerifyCode(any()))
                .thenReturn(new MobileSmsAuthProvider.VerifyResult(true, null, null, null, null, null));
    }

    private String body() {
        return "{\"phone\":\"%s\",\"smsCode\":\"%s\"}".formatted(PHONE, SMS_CODE);
    }

    @Test
    void requestDeletion_happyPath_marksPendingAndReturnsScheduledAt() throws Exception {
        stubAuthAndSms();
        when(membershipRepository.markPendingDeletion(5L, "careermate"))
                .thenReturn(Instant.parse("2026-08-11T00:00:00Z"));

        mockMvc.perform(post("/auth/apps/careermate/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.app").value("careermate"))
                .andExpect(jsonPath("$.deletionScheduledAt").isString());

        verify(membershipRepository).markPendingDeletion(5L, "careermate");
    }

    @Test
    void requestDeletion_unsupportedApp_returns400Friendly() throws Exception {
        mockMvc.perform(post("/auth/apps/unknownapp/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("APP_NOT_SUPPORTED"))
                .andExpect(jsonPath("$.message").value("不支持的应用"));
    }

    @Test
    void requestDeletion_noMembership_returns404Friendly() throws Exception {
        stubAuthAndSms();
        when(membershipRepository.markPendingDeletion(5L, "careermate")).thenReturn(null);

        mockMvc.perform(post("/auth/apps/careermate/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("APP_MEMBERSHIP_NOT_FOUND"))
                .andExpect(jsonPath("$.message").value("当前账号未开通该应用，无需注销"));
    }

    @Test
    void requestDeletion_phoneMismatch_returns400() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        String otherHash = PhoneSupport.hashPhone("13900000002", PEPPER);
        when(userRepository.findById(5L))
                .thenReturn(Optional.of(new AuthUser(5L, otherHash, null, "alice", null, "USER", 1L, "ACTIVE", null)));

        mockMvc.perform(post("/auth/apps/careermate/deletion-request")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON).content(body()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("PHONE_MISMATCH"));
    }

    @Test
    void cancelDeletion_happyPath_returnsActive() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        when(membershipRepository.cancelDeletion(5L, "careermate")).thenReturn(1);

        mockMvc.perform(delete("/auth/apps/careermate/deletion-request")
                        .header("Authorization", "Bearer tok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void cancelDeletion_notPending_returns400Friendly() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        when(membershipRepository.cancelDeletion(5L, "careermate")).thenReturn(0);

        mockMvc.perform(delete("/auth/apps/careermate/deletion-request")
                        .header("Authorization", "Bearer tok"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("NOT_PENDING_DELETION"))
                .andExpect(jsonPath("$.message").value("该应用当前未处于注销冷静期"));
    }

    @Test
    void deletionStatus_pending_returnsPendingTrue() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
        when(membershipRepository.find(5L, "careermate"))
                .thenReturn(Optional.of(new AppMembership(5L, "careermate", "USER", "PENDING_DELETION")));

        mockMvc.perform(get("/auth/apps/careermate/deletion-status")
                        .header("Authorization", "Bearer tok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PENDING_DELETION"))
                .andExpect(jsonPath("$.pendingDeletion").value(true));
    }
}
