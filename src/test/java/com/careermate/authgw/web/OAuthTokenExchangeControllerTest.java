package com.careermate.authgw.web;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.oauth.TokenExchangeService;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(OAuthTokenExchangeController.class)
class OAuthTokenExchangeControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean ClientAuthenticator clientAuthenticator;
    @MockitoBean TokenExchangeService tokenExchangeService;
    @MockitoBean AuditLogService auditLogService;

    @Test
    void exchangeReturnsTokenResponse() throws Exception {
        OAuthClient client = client();
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion")).thenReturn(client);
        when(tokenExchangeService.exchange(client, TokenExchangeService.GRANT_TYPE, "subject",
                TokenExchangeService.ACCESS_TOKEN_TYPE, "ragforge-admin-api", "rag:search"))
                .thenReturn(new TokenExchangeService.TokenExchangeResult("access",
                        "urn:ietf:params:oauth:token-type:access_token", "Bearer", 600, "rag:search"));

        mockMvc.perform(post("/oauth/token-exchange")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", TokenExchangeService.GRANT_TYPE)
                        .param("subject_token", "subject")
                        .param("subject_token_type", TokenExchangeService.ACCESS_TOKEN_TYPE)
                        .param("requested_audience", "ragforge-admin-api")
                        .param("requested_scopes", "rag:search")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "assertion"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("access"))
                .andExpect(jsonPath("$.issued_token_type").value("urn:ietf:params:oauth:token-type:access_token"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(600))
                .andExpect(jsonPath("$.scope").value("rag:search"));
    }

    @Test
    void clientAuthFailureIsAuditedAndMapped() throws Exception {
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "bad"))
                .thenThrow(new AuthException(401, "CLIENT_ASSERTION_INVALID", "bad"));

        mockMvc.perform(post("/oauth/token-exchange")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", TokenExchangeService.GRANT_TYPE)
                        .param("subject_token", "subject")
                        .param("subject_token_type", TokenExchangeService.ACCESS_TOKEN_TYPE)
                        .param("requested_audience", "ragforge-admin-api")
                        .param("requested_scopes", "rag:search")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "bad"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("CLIENT_ASSERTION_INVALID"));
        verify(auditLogService).high(org.mockito.ArgumentMatchers.eq("token_exchange.client_auth_failed"),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.eq("client"), org.mockito.ArgumentMatchers.anyMap());
    }

    @Test
    void exchangeServiceAuthExceptionIsMapped() throws Exception {
        OAuthClient client = client();
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion")).thenReturn(client);
        when(tokenExchangeService.exchange(org.mockito.ArgumentMatchers.eq(client), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                .thenThrow(new AuthException(403, "SCOPE_NOT_ALLOWED", "scope denied"));

        mockMvc.perform(post("/oauth/token-exchange")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", TokenExchangeService.GRANT_TYPE)
                        .param("subject_token", "subject")
                        .param("subject_token_type", TokenExchangeService.ACCESS_TOKEN_TYPE)
                        .param("requested_audience", "ragforge-admin-api")
                        .param("requested_scopes", "rag:admin:write")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "assertion"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("SCOPE_NOT_ALLOWED"));
    }

    private OAuthClient client() {
        return new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of(TokenExchangeService.GRANT_TYPE), Set.of("ragforge-admin-api"), Set.of("rag:search"), "ACTIVE");
    }
}
