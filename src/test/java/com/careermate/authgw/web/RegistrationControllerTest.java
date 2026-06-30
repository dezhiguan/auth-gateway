package com.careermate.authgw.web;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.RegistrationService;
import com.careermate.authgw.sms.SmsException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(RegistrationController.class)
class RegistrationControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean RegistrationService registrationService;

    @Test
    void registerReturnsCreatedMessageForNewUser() throws Exception {
        when(registrationService.register("13800000000", "123456", "amy", "amy@example.com", "Passw0rd", "ragforge"))
                .thenReturn(new RegistrationService.RegisterResult(12, false));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","smsCode":"123456","username":"amy","email":"amy@example.com","password":"Passw0rd","app":"ragforge"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(12))
                .andExpect(jsonPath("$.linked").value(false))
                .andExpect(jsonPath("$.message").value("注册成功"));
    }

    @Test
    void registerReturnsLinkedMessageForExistingUser() throws Exception {
        when(registrationService.register("13800000000", "123456", null, null, null, "careermate"))
                .thenReturn(new RegistrationService.RegisterResult(15, true));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","smsCode":"123456","app":"careermate"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(15))
                .andExpect(jsonPath("$.linked").value(true))
                .andExpect(jsonPath("$.message").value("该手机号已注册，已为你关联并补全账号信息"));
    }

    @Test
    void registerMapsAuthAndSmsExceptions() throws Exception {
        when(registrationService.register("13800000000", "bad", null, null, null, "ragforge"))
                .thenThrow(new AuthException(401, "SMS_CODE_INVALID", "bad code"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","smsCode":"bad","app":"ragforge"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SMS_CODE_INVALID"));

        when(registrationService.register("13900000000", "123456", null, null, null, "ragforge"))
                .thenThrow(new SmsException(429, "SMS_SEND_TOO_FREQUENT", "too frequent"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13900000000","smsCode":"123456","app":"ragforge"}
                                """))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("SMS_SEND_TOO_FREQUENT"));
    }
}
