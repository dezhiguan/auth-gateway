package com.careermate.authgw.web;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.oauth.ClientAuthenticator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(InternalUserController.class)
class InternalUserControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean ClientAuthenticator clientAuthenticator;
    @MockitoBean AuthUserRepository userRepository;

    @Test
    void invalidateSessionIncrementsVersionAndReturnsTrue() throws Exception {
        mockMvc.perform(post("/internal/users/42/invalidate-session")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("client_id", "ragforge")
                        .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        .param("client_assertion", "signed.jwt.token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.invalidated").value(true))
                .andExpect(jsonPath("$.userId").value(42));

        verify(clientAuthenticator).authenticate("ragforge",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "signed.jwt.token");
        verify(userRepository).incrementSessionVersion(42L);
    }

    @Test
    void invalidateSessionReturns401WhenClientAuthFails() throws Exception {
        doThrow(new AuthException(401, "CLIENT_AUTH_FAILED", "invalid client"))
                .when(clientAuthenticator).authenticate(null, null, null);

        mockMvc.perform(post("/internal/users/10/invalidate-session")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("CLIENT_AUTH_FAILED"));
    }
}
