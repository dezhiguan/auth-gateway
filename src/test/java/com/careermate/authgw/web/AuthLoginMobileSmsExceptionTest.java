package com.careermate.authgw.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.LoginService;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.sms.SmsException;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AuthLoginController.class)
class AuthLoginMobileSmsExceptionTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private ClientAuthenticator clientAuthenticator;

    @MockitoBean
    private LoginService loginService;

    @Test
    void smsExceptionShouldNotReturn500InternalServerError() throws Exception {
        when(clientAuthenticator.authenticate(anyString(), anyString(), anyString()))
                .thenReturn(new OAuthClient(
                        "ragforge-admin-backend",
                        "ragforge",
                        "private_key_jwt",
                        null,
                        Set.of("password", "refresh_token"),
                        Set.of("ragforge-admin-api"),
                        Set.of("rag:admin:read"),
                        "ACTIVE"));
        when(loginService.loginMobile(anyString(), anyString(), anyString(), any()))
                .thenThrow(new SmsException(502, "SMS_PROVIDER_ERROR", "验证码暂时无法校验，请稍后再试"));

        mockMvc.perform(post("/auth/login/mobile")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("phone", "13800000000")
                        .param("code", "123456")
                        .param("target_aud", "ragforge-admin-api")
                        .param("client_id", "ragforge-admin-backend"))
                .andExpect(status().is(502))
                .andExpect(jsonPath("$.error").value("SMS_PROVIDER_ERROR"));
    }
}
