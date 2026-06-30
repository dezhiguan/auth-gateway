package com.careermate.authgw.web;

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
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(UserInfoController.class)
class UserInfoControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean TokenStatusService tokenStatusService;
    @MockitoBean ClientAuthenticator clientAuthenticator;

    @Test
    void userInfoReturnsActiveTokenInfo() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:12").claim("user_id", 12L).build();
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(claims);
        when(tokenStatusService.userInfo(claims)).thenReturn(Map.of(
                "sub", "user:12",
                "user_id", 12L,
                "scopes", List.of("rag:search")));

        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer access"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("user:12"))
                .andExpect(jsonPath("$.user_id").value(12))
                .andExpect(jsonPath("$.scopes[0]").value("rag:search"));
    }

    @Test
    void userInfoMapsAccessTokenError() throws Exception {
        when(accessTokenVerifier.verify(null)).thenThrow(new AuthException(401, "ACCESS_TOKEN_REQUIRED", "missing"));

        mockMvc.perform(get("/userinfo"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("ACCESS_TOKEN_REQUIRED"));
    }

    @Test
    void introspectionReturnsActiveAndInactiveResults() throws Exception {
        OAuthClient client = client();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user:12").build();
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion")).thenReturn(client);
        when(accessTokenVerifier.verifyToken("token")).thenReturn(claims);
        when(tokenStatusService.introspection(claims, client)).thenReturn(Map.of("active", true, "sub", "user:12"));

        mockMvc.perform(post("/oauth/introspect")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", "token")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "assertion"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.sub").value("user:12"));

        when(accessTokenVerifier.verifyToken("bad-token"))
                .thenThrow(new AuthException(401, "ACCESS_TOKEN_INVALID", "invalid"));
        mockMvc.perform(post("/oauth/introspect")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", "bad-token")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "assertion"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void introspectionMapsClientAuthenticationFailure() throws Exception {
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "bad"))
                .thenThrow(new AuthException(401, "CLIENT_ASSERTION_INVALID", "bad"));

        mockMvc.perform(post("/oauth/introspect")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", "token")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "bad"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("CLIENT_ASSERTION_INVALID"));
    }

    private OAuthClient client() {
        return new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of("token_exchange"), Set.of("careermate-api"), Set.of("rag:search"), "ACTIVE");
    }
}
