package com.careermate.authgw.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenPair;
import com.careermate.authgw.auth.TokenService;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AuthTokenController.class)
class AuthTokenControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean ClientAuthenticator clientAuthenticator;
    @MockitoBean AccessTokenVerifier accessTokenVerifier;
    @MockitoBean TokenService tokenService;

    @Test
    void refreshReturnsOAuthTokenResponse() throws Exception {
        OAuthClient client = client();
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion")).thenReturn(client);
        when(tokenService.refresh("refresh-token", client)).thenReturn(new TokenPair("access", "refresh2", "Bearer", 900));

        mockMvc.perform(post("/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("refresh_token", "refresh-token")
                        .param("client_id", "client")
                        .param("client_assertion_type", ClientAuthenticator.ASSERTION_TYPE)
                        .param("client_assertion", "assertion"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("access"))
                .andExpect(jsonPath("$.refresh_token").value("refresh2"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900));
    }

    @Test
    void refreshMapsAuthException() throws Exception {
        when(clientAuthenticator.authenticate(eq("client"), any(), any()))
                .thenThrow(new AuthException(401, "CLIENT_ASSERTION_INVALID", "bad assertion"));

        mockMvc.perform(post("/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("refresh_token", "refresh-token")
                        .param("client_id", "client"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("CLIENT_ASSERTION_INVALID"));
    }

    @Test
    void logoutVerifiesBearerAndRevokesSession() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("session_id", "sid-1").build();
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(claims);

        mockMvc.perform(post("/auth/logout").header("Authorization", "Bearer access"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));
        verify(tokenService).logout(claims);
    }

    @Test
    void logoutAllPassesPasswordToService() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();
        when(accessTokenVerifier.verify("Bearer access")).thenReturn(claims);

        mockMvc.perform(post("/auth/logout-all")
                        .header("Authorization", "Bearer access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"secret\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));
        verify(tokenService).logoutAll(claims, "secret");
    }

    private OAuthClient client() {
        return new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of("refresh_token"), Set.of("careermate-api"), Set.of("rag:search"), "ACTIVE");
    }
}
