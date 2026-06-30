package com.careermate.authgw.web;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.PasswordResetService;
import com.careermate.authgw.auth.TokenPair;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.sms.SmsException;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(PasswordResetController.class)
class PasswordResetControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean PasswordResetService passwordResetService;
    @MockitoBean ClientAuthenticator clientAuthenticator;

    @Test
    void initReturnsEnumerationSafeResponse() throws Exception {
        when(passwordResetService.init("amy", "13800000000"))
                .thenReturn(new PasswordResetService.ResetInitResult("***********", true));

        mockMvc.perform(post("/auth/password/reset/init")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"account\":\"amy\",\"phone\":\"13800000000\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.masked_phone").value("***********"))
                .andExpect(jsonPath("$.ticket_required").value(true));
    }

    @Test
    void verifyReturnsResetTicket() throws Exception {
        when(passwordResetService.verify("amy", "13800000000", "123456")).thenReturn("ticket-1");

        mockMvc.perform(post("/auth/password/reset/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"account\":\"amy\",\"phone\":\"13800000000\",\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reset_ticket").value("ticket-1"));
    }

    @Test
    void confirmAuthenticatesClientAndReturnsTokens() throws Exception {
        OAuthClient client = client();
        when(clientAuthenticator.authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion")).thenReturn(client);
        when(passwordResetService.confirm("ticket-1", "Newpass1", client, "careermate-api"))
                .thenReturn(new TokenPair("access", "refresh", "Bearer", 900));

        mockMvc.perform(post("/auth/password/reset/confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"reset_ticket":"ticket-1","new_password":"Newpass1","target_aud":"careermate-api","client_id":"client","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":"assertion"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("access"))
                .andExpect(jsonPath("$.refresh_token").value("refresh"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900));
    }

    @Test
    void mapsAuthAndSmsExceptions() throws Exception {
        when(passwordResetService.verify("amy", "13800000000", "bad"))
                .thenThrow(new AuthException(401, "SMS_CODE_INVALID", "bad code"));

        mockMvc.perform(post("/auth/password/reset/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"account\":\"amy\",\"phone\":\"13800000000\",\"code\":\"bad\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SMS_CODE_INVALID"));

        when(passwordResetService.init("amy", "13900000000"))
                .thenThrow(new SmsException(502, "SMS_PROVIDER_ERROR", "provider down"));

        mockMvc.perform(post("/auth/password/reset/init")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"account\":\"amy\",\"phone\":\"13900000000\"}"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("SMS_PROVIDER_ERROR"));
    }

    private OAuthClient client() {
        return new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of("password"), Set.of("careermate-api"), Set.of("rag:search"), "ACTIVE");
    }
}
