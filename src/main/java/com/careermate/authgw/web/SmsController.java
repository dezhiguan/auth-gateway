package com.careermate.authgw.web;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsException;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SmsController {

    private final MobileSmsAuthProvider smsProvider;
    private final SmsAuthRateLimiter rateLimiter;
    private final SmsProperties properties;

    public SmsController(
            MobileSmsAuthProvider smsProvider,
            SmsAuthRateLimiter rateLimiter,
            SmsProperties properties) {
        this.smsProvider = smsProvider;
        this.rateLimiter = rateLimiter;
        this.properties = properties;
    }

    @PostMapping("/auth/sms/send")
    public ResponseEntity<SmsSendResponse> send(
            @RequestBody SmsSendRequest request,
            HttpServletRequest servletRequest) {
        SmsScene scene = SmsScene.fromValue(request.scene());
        if (scene == null) {
            throw new SmsException(400, "SMS_SCENE_INVALID", "验证码场景不正确，请刷新页面后重试");
        }

        String phone = PhoneSupport.requireMainlandPhone(request.phone());
        String ip = clientIp(servletRequest);
        String phoneHash = PhoneSupport.hashPhone(phone, properties.getPhoneHashPepper());
        String ipHash = PhoneSupport.hashIp(ip, properties.getPhoneHashPepper());

        rateLimiter.checkSendAllowed(scene, phoneHash, ipHash, PhoneSupport.maskPhone(phone));

        String code = resolveCode();
        MobileSmsAuthProvider.SendResult result = smsProvider.sendVerifyCode(
                new MobileSmsAuthProvider.SendRequest(phone, scene, code));
        if (!result.success()) {
            throw new SmsException(502, "SMS_PROVIDER_SEND_FAILED", "短信服务暂时不可用，请稍后再试");
        }

        String codeHash = PhoneSupport.hashCode(code, properties.getPhoneHashPepper());
        rateLimiter.storePendingCode(scene, phoneHash, codeHash, result.outId());
        rateLimiter.recordSend(scene, phoneHash, ipHash);

        return ResponseEntity.ok(new SmsSendResponse(true, properties.getCodeTtlSeconds()));
    }

    @ExceptionHandler(SmsException.class)
    public ResponseEntity<Map<String, Object>> handleSmsException(SmsException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    private String resolveCode() {
        if (StringUtils.hasText(properties.getMockCode())) {
            return properties.getMockCode();
        }
        return PhoneSupport.generateNumericCode(6);
    }

    private String clientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwardedFor)) {
            return PhoneSupport.normalizeIp(forwardedFor);
        }
        return PhoneSupport.normalizeIp(request.getRemoteAddr());
    }

    public record SmsSendRequest(String phone, String scene, String captcha) {
    }

    @JsonPropertyOrder({"sent", "expires_in"})
    public record SmsSendResponse(boolean sent, @JsonProperty("expires_in") long expiresIn) {
    }
}
