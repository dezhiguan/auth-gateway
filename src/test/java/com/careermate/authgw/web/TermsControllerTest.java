package com.careermate.authgw.web;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.audit.AuditLogService;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(TermsController.class)
class TermsControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean AuthUserRepository userRepository;
    @MockitoBean AuditLogService auditLogService;

    @Test
    void acceptTermsUpdatesDbAndReturnsAccepted() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:7").claim("user_id", 7L).build();
        when(accessTokenVerifier.verify("Bearer tok")).thenReturn(claims);

        mockMvc.perform(post("/auth/users/me/terms-acceptance")
                        .header("Authorization", "Bearer tok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"termsVersion":"1.0"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(true))
                .andExpect(jsonPath("$.termsVersion").value("1.0"));

        verify(userRepository).updateTermsAcceptance(7L, "1.0");
    }

    @Test
    void acceptTermsDefaultsToV1WhenVersionMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:8").claim("user_id", 8L).build();
        when(accessTokenVerifier.verify("Bearer tok2")).thenReturn(claims);

        mockMvc.perform(post("/auth/users/me/terms-acceptance")
                        .header("Authorization", "Bearer tok2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.termsVersion").value("1.0"));

        verify(userRepository).updateTermsAcceptance(8L, "1.0");
    }

    @Test
    void acceptTermsRejectsUnknownVersion() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:9").claim("user_id", 9L).build();
        when(accessTokenVerifier.verify("Bearer tok9")).thenReturn(claims);

        mockMvc.perform(post("/auth/users/me/terms-acceptance")
                        .header("Authorization", "Bearer tok9")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"termsVersion\":\"999\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("TERMS_VERSION_INVALID"));

        org.mockito.Mockito.verify(userRepository, org.mockito.Mockito.never())
                .updateTermsAcceptance(org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void acceptTermsReturns401WhenTokenInvalid() throws Exception {
        when(accessTokenVerifier.verify("Bearer bad"))
                .thenThrow(new AuthException(401, "ACCESS_TOKEN_INVALID", "invalid"));

        mockMvc.perform(post("/auth/users/me/terms-acceptance")
                        .header("Authorization", "Bearer bad")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"termsVersion":"1.0"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("ACCESS_TOKEN_INVALID"));
    }
}
