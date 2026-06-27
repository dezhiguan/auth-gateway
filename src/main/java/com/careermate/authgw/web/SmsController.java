package com.careermate.authgw.web;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.careermate.authgw.auth.AuthUser;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.auth.MembershipRepository;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsException;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import java.util.Optional;
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

    /** 在登录场景下要求"必须已注册"的 App（其登录非注册一体，发码前先校验准入，避免给未注册号码白发短信）。 */
    private static final String LOGIN_REQUIRES_MEMBERSHIP_APP = "ragforge";

    private final MobileSmsAuthProvider smsProvider;
    private final SmsAuthRateLimiter rateLimiter;
    private final SmsProperties properties;
    private final AuthUserRepository authUserRepository;
    private final MembershipRepository membershipRepository;

    public SmsController(
            MobileSmsAuthProvider smsProvider,
            SmsAuthRateLimiter rateLimiter,
            SmsProperties properties,
            AuthUserRepository authUserRepository,
            MembershipRepository membershipRepository) {
        this.smsProvider = smsProvider;
        this.rateLimiter = rateLimiter;
        this.properties = properties;
        this.authUserRepository = authUserRepository;
        this.membershipRepository = membershipRepository;
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

        // 登录场景下，对"登录非注册一体"的 App（如 ragforge）先校验准入：未注册则不发短信，避免浪费。
        // 注意：CareerMate 移动端登录注册一体，不传 app（或非 ragforge），此处不拦截。
        if (scene == SmsScene.LOGIN && LOGIN_REQUIRES_MEMBERSHIP_APP.equalsIgnoreCase(request.app())) {
            requireRegisteredForLogin(phoneHash);
        }

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

    /** 校验该手机号已注册且具备目标 App 准入；否则返回 409，调用方据此提示"请先注册"。 */
    private void requireRegisteredForLogin(String phoneHash) {
        Optional<AuthUser> user = authUserRepository.findByPhoneHash(phoneHash);
        boolean registered = user
                .flatMap(u -> membershipRepository.find(u.id(), LOGIN_REQUIRES_MEMBERSHIP_APP))
                .isPresent();
        if (!registered) {
            throw new SmsException(
                    409, "SMS_LOGIN_NOT_REGISTERED", "该手机号尚未注册 RAGForge，请先完成注册");
        }
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

    public record SmsSendRequest(String phone, String scene, String captcha, String app) {
    }

    @JsonPropertyOrder({"sent", "expires_in"})
    public record SmsSendResponse(boolean sent, @JsonProperty("expires_in") long expiresIn) {
    }
}
