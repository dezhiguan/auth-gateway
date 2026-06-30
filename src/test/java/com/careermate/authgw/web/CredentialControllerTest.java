package com.careermate.authgw.web;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.CredentialService;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(CredentialController.class)
class CredentialControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean CredentialService credentialService;

    @Test
    void setPasswordBindEmailAndSetUsernameUseCurrentUserId() throws Exception {
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(claims(12));

        mockMvc.perform(post("/auth/credential/set-password")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"oldPassword\":\"old\",\"newPassword\":\"Newpass1\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        verify(credentialService).setPassword(12, "old", "Newpass1");

        mockMvc.perform(post("/auth/credential/bind-email")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"amy@example.com\",\"password\":\"secret\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        verify(credentialService).bindEmail(12, "amy@example.com", "secret");

        mockMvc.perform(post("/auth/credential/set-username")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"amy\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        verify(credentialService).setUsername(12, "amy");
    }

    @Test
    void missingUserIdClaimReturnsAccessTokenInvalid() throws Exception {
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(new JWTClaimsSet.Builder().build());

        mockMvc.perform(post("/auth/credential/set-password")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"newPassword\":\"Newpass1\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("ACCESS_TOKEN_INVALID"));
    }

    @Test
    void serviceAuthExceptionIsMapped() throws Exception {
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(claims(12));
        org.mockito.Mockito.doThrow(new AuthException(409, "EMAIL_TAKEN", "email taken"))
                .when(credentialService).bindEmail(12, "amy@example.com", "secret");

        mockMvc.perform(post("/auth/credential/bind-email")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"amy@example.com\",\"password\":\"secret\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("EMAIL_TAKEN"));
    }

    private JWTClaimsSet claims(long userId) {
        return new JWTClaimsSet.Builder().claim("user_id", userId).build();
    }
}
