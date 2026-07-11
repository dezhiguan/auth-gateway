package com.careermate.authgw.web;

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
import com.careermate.authgw.auth.MembershipRepository;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AppDeletionController.class)
class AppDeletionControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean MembershipRepository membershipRepository;
    @MockitoBean AuditLogService auditLogService;

    private void stubAuth() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").claim("user_id", 5L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);
    }

    @Test
    void requestDeletion_happyPath_marksPendingAndReturnsScheduledAt() throws Exception {
        stubAuth();
        when(membershipRepository.markPendingDeletion(5L, "careermate"))
                .thenReturn(Instant.parse("2026-08-11T00:00:00Z"));

        mockMvc.perform(post("/auth/apps/careermate/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.app").value("careermate"))
                .andExpect(jsonPath("$.deletionScheduledAt").isString());

        verify(membershipRepository).markPendingDeletion(5L, "careermate");
    }

    @Test
    void requestDeletion_unsupportedApp_returns400Friendly() throws Exception {
        mockMvc.perform(post("/auth/apps/unknownapp/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("APP_NOT_SUPPORTED"))
                .andExpect(jsonPath("$.message").value("不支持的应用"));
    }

    @Test
    void requestDeletion_noMembership_returns404Friendly() throws Exception {
        stubAuth();
        when(membershipRepository.markPendingDeletion(5L, "careermate")).thenReturn(null);

        mockMvc.perform(post("/auth/apps/careermate/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("APP_MEMBERSHIP_NOT_FOUND"))
                .andExpect(jsonPath("$.message").value("当前账号未开通该应用，无需注销"));
    }

    @Test
    void requestDeletion_missingUserId_returns401() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:5").build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);

        mockMvc.perform(post("/auth/apps/careermate/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("ACCESS_TOKEN_INVALID"));
    }

    @Test
    void cancelDeletion_happyPath_returnsActive() throws Exception {
        stubAuth();
        when(membershipRepository.cancelDeletion(5L, "careermate")).thenReturn(1);

        mockMvc.perform(delete("/auth/apps/careermate/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void cancelDeletion_notPending_returns400Friendly() throws Exception {
        stubAuth();
        when(membershipRepository.cancelDeletion(5L, "careermate")).thenReturn(0);

        mockMvc.perform(delete("/auth/apps/careermate/deletion-request").header("Authorization", "Bearer tok"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("NOT_PENDING_DELETION"))
                .andExpect(jsonPath("$.message").value("该应用当前未处于注销冷静期"));
    }

    @Test
    void deletionStatus_pending_returnsPendingTrue() throws Exception {
        stubAuth();
        when(membershipRepository.find(5L, "careermate"))
                .thenReturn(Optional.of(new AppMembership(5L, "careermate", "USER", "PENDING_DELETION")));

        mockMvc.perform(get("/auth/apps/careermate/deletion-status").header("Authorization", "Bearer tok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PENDING_DELETION"))
                .andExpect(jsonPath("$.pendingDeletion").value(true));
    }
}
