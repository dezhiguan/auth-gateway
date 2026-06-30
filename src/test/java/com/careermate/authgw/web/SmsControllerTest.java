package com.careermate.authgw.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.careermate.authgw.auth.AppMembership;
import com.careermate.authgw.auth.AuthUser;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.auth.MembershipRepository;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(SmsController.class)
class SmsControllerTest {

    private static final String PEPPER = "pepper";

    @Autowired MockMvc mockMvc;
    @MockitoBean MobileSmsAuthProvider smsProvider;
    @MockitoBean SmsAuthRateLimiter rateLimiter;
    @MockitoBean SmsProperties properties;
    @MockitoBean AuthUserRepository authUserRepository;
    @MockitoBean MembershipRepository membershipRepository;

    @BeforeEach
    void setUp() {
        when(properties.getPhoneHashPepper()).thenReturn(PEPPER);
        when(properties.getMockCode()).thenReturn("123456");
        when(properties.getCodeTtlSeconds()).thenReturn(300);
    }

    @Test
    void sendStoresPendingCodeAndRecordsLimiterState() throws Exception {
        when(smsProvider.sendVerifyCode(any()))
                .thenReturn(new MobileSmsAuthProvider.SendResult(true, "out-1", "req-1", "OK", "sent"));

        mockMvc.perform(post("/auth/sms/send")
                        .header("X-Forwarded-For", "10.1.2.3, 10.9.9.9")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","scene":"register"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sent").value(true))
                .andExpect(jsonPath("$.expires_in").value(300));

        String phoneHash = PhoneSupport.hashPhone("13800000000", PEPPER);
        String ipHash = PhoneSupport.hashIp("10.1.2.3", PEPPER);
        String codeHash = PhoneSupport.hashCode("123456", PEPPER);
        verify(rateLimiter).checkSendAllowed(SmsScene.REGISTER, phoneHash, ipHash, "138****0000");
        verify(rateLimiter).storePendingCode(SmsScene.REGISTER, phoneHash, codeHash, "out-1");
        verify(rateLimiter).recordSend(SmsScene.REGISTER, phoneHash, ipHash);

        ArgumentCaptor<MobileSmsAuthProvider.SendRequest> captor =
                ArgumentCaptor.forClass(MobileSmsAuthProvider.SendRequest.class);
        verify(smsProvider).sendVerifyCode(captor.capture());
        assertThat(captor.getValue().phone()).isEqualTo("13800000000");
        assertThat(captor.getValue().scene()).isEqualTo(SmsScene.REGISTER);
        assertThat(captor.getValue().code()).isEqualTo("123456");
    }

    @Test
    void sendRejectsInvalidSceneBeforeProviderCall() throws Exception {
        mockMvc.perform(post("/auth/sms/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","scene":"unknown"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("SMS_SCENE_INVALID"));

        verify(smsProvider, never()).sendVerifyCode(any());
        verify(rateLimiter, never()).checkSendAllowed(any(), anyString(), anyString(), anyString());
    }

    @Test
    void sendMapsProviderFailureToSmsBusinessError() throws Exception {
        when(smsProvider.sendVerifyCode(any()))
                .thenReturn(new MobileSmsAuthProvider.SendResult(false, "out-1", "req-1", "E", "failed"));

        mockMvc.perform(post("/auth/sms/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","scene":"reset"}
                                """))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("SMS_PROVIDER_SEND_FAILED"));

        verify(rateLimiter, never()).storePendingCode(any(), anyString(), anyString(), anyString());
        verify(rateLimiter, never()).recordSend(any(), anyString(), anyString());
    }

    @Test
    void sendRejectsRagforgeLoginWhenPhoneIsNotRegistered() throws Exception {
        String phoneHash = PhoneSupport.hashPhone("13800000000", PEPPER);
        when(authUserRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.empty());

        mockMvc.perform(post("/auth/sms/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","scene":"login","app":"ragforge"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("SMS_LOGIN_NOT_REGISTERED"));

        verify(smsProvider, never()).sendVerifyCode(any());
    }

    @Test
    void sendAllowsRagforgeLoginForRegisteredMember() throws Exception {
        String phoneHash = PhoneSupport.hashPhone("13800000000", PEPPER);
        AuthUser user = new AuthUser(7, phoneHash, null, "amy", null, "USER", 1, "ACTIVE");
        when(authUserRepository.findByPhoneHash(phoneHash)).thenReturn(Optional.of(user));
        when(membershipRepository.find(7, "ragforge"))
                .thenReturn(Optional.of(new AppMembership(7, "ragforge", "USER", "ACTIVE")));
        when(smsProvider.sendVerifyCode(any()))
                .thenReturn(new MobileSmsAuthProvider.SendResult(true, "out-login", "req-1", "OK", "sent"));

        mockMvc.perform(post("/auth/sms/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"phone":"13800000000","scene":"login","app":"ragforge"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sent").value(true));

        verify(membershipRepository).find(7, "ragforge");
        verify(rateLimiter).storePendingCode(eq(SmsScene.LOGIN), eq(phoneHash), anyString(), eq("out-login"));
    }
}
