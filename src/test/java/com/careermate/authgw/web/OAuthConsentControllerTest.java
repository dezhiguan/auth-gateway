package com.careermate.authgw.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenStatusService;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.oauth.ConsentService;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(OAuthConsentController.class)
class OAuthConsentControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean TokenStatusService tokenStatusService;
    @MockitoBean ConsentService consentService;
    @MockitoBean ClientAuthenticator clientAuthenticator;

    @Test
    void createListAndRevokeConsent() throws Exception {
        JWTClaimsSet claims = claims();
        ConsentService.ConsentRecord record = record("consent-1");
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(claims);
        when(consentService.create(eq(claims), eq("agent-client"), eq(Set.of("rag:search")), eq(List.of(100L)), eq(600L)))
                .thenReturn(record);
        when(consentService.list(claims)).thenReturn(List.of(record));

        mockMvc.perform(post("/oauth/consents")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_principal_id":"agent-client","scopes":["rag:search"],"allowed_kb_ids":[100],"expires_in_seconds":600}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.consent_id").value("consent-1"))
                .andExpect(jsonPath("$.client_principal_id").value("agent-client"))
                .andExpect(jsonPath("$.allowed_kb_ids[0]").value(100))
                .andExpect(jsonPath("$.active").value(true));

        mockMvc.perform(get("/oauth/consents").header("Authorization", "Bearer access"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].consent_id").value("consent-1"));

        mockMvc.perform(post("/oauth/consents/consent-1/revoke").header("Authorization", "Bearer access"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));
        verify(consentService).revoke(claims, "consent-1");
    }

    @Test
    void createMapsAuthException() throws Exception {
        JWTClaimsSet claims = claims();
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(claims);
        when(consentService.create(any(), any(), any(), any(), any()))
                .thenThrow(new AuthException(403, "SCOPE_NOT_ALLOWED", "scope denied"));

        mockMvc.perform(post("/oauth/consents")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_principal_id":"agent-client","scopes":["rag:admin:write"]}
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("SCOPE_NOT_ALLOWED"));
    }

    @Test
    void delegationTokenReturnsOAuthTokenResponse() throws Exception {
        OAuthClient client = client();
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion")).thenReturn(client);
        when(consentService.parseScopes("rag:search")).thenReturn(Set.of("rag:search"));
        when(consentService.issueDelegationToken(client, "consent-1", "ragforge-admin-api", Set.of("rag:search")))
                .thenReturn(new ConsentService.DelegationToken("access", "Bearer",
                        "urn:ietf:params:oauth:token-type:access_token", 600, "rag:search"));

        mockMvc.perform(post("/oauth/delegation-token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("consent_id", "consent-1")
                        .param("requested_audience", "ragforge-admin-api")
                        .param("requested_scopes", "rag:search")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "assertion"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("access"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.scope").value("rag:search"));
    }

    private JWTClaimsSet claims() {
        return new JWTClaimsSet.Builder().claim("user_id", 12L).build();
    }

    private ConsentService.ConsentRecord record(String id) {
        return new ConsentService.ConsentRecord(id, 12, "agent-client", Set.of("rag:search"),
                List.of(100L), Instant.now().plusSeconds(600), null);
    }

    private OAuthClient client() {
        return new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of("token_exchange"), Set.of("ragforge-admin-api"), Set.of("rag:search"), "ACTIVE");
    }
}
