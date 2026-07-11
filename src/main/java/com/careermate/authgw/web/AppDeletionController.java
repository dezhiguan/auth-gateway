package com.careermate.authgw.web;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AppMembership;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.auth.MembershipRepository;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * 应用级注销：只退某个 App（careermate / ragforge），不动共享身份与其他 App 准入。
 *
 * <p>POST（申请注销）：Bearer 识别用户 + phone+smsCode 二次验证 → 该 App membership 进入 30 天冷静期。
 * DELETE（撤销）：Bearer 识别用户 → membership 恢复 ACTIVE。
 * GET（查状态）：供前端"注销中"中间页展示剩余天数。</p>
 */
@RestController
public class AppDeletionController {

    private static final Set<String> ALLOWED_APPS = Set.of("careermate", "ragforge");

    private final AccessTokenVerifier accessTokenVerifier;
    private final AuthUserRepository userRepository;
    private final MembershipRepository membershipRepository;
    private final MobileSmsAuthProvider smsProvider;
    private final SmsAuthRateLimiter smsRateLimiter;
    private final SmsProperties smsProperties;
    private final AuditLogService auditLogService;

    public AppDeletionController(
            AccessTokenVerifier accessTokenVerifier,
            AuthUserRepository userRepository,
            MembershipRepository membershipRepository,
            MobileSmsAuthProvider smsProvider,
            SmsAuthRateLimiter smsRateLimiter,
            SmsProperties smsProperties,
            AuditLogService auditLogService) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.smsProvider = smsProvider;
        this.smsRateLimiter = smsRateLimiter;
        this.smsProperties = smsProperties;
        this.auditLogService = auditLogService;
    }

    @PostMapping(value = "/auth/apps/{app}/deletion-request", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> requestDeletion(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("app") String app,
            @RequestBody DeletionRequest request) {
        String normalizedApp = requireAllowedApp(app);
        long userId = currentUserId(authorization);
        verifySmsForUser(userId, request.phone(), request.smsCode());
        Instant scheduledAt = membershipRepository.markPendingDeletion(userId, normalizedApp);
        if (scheduledAt == null) {
            throw new AuthException(404, "APP_MEMBERSHIP_NOT_FOUND", "当前账号未开通该应用，无需注销");
        }
        auditLogService.high("app.deletion.requested", userId, null, Map.of("app", normalizedApp));
        return Map.of("app", normalizedApp, "deletionScheduledAt", scheduledAt.toString());
    }

    @DeleteMapping("/auth/apps/{app}/deletion-request")
    public Map<String, Object> cancelDeletion(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("app") String app) {
        String normalizedApp = requireAllowedApp(app);
        long userId = currentUserId(authorization);
        int updated = membershipRepository.cancelDeletion(userId, normalizedApp);
        if (updated != 1) {
            throw new AuthException(400, "NOT_PENDING_DELETION", "该应用当前未处于注销冷静期");
        }
        auditLogService.info("app.deletion.cancelled", userId, null, Map.of("app", normalizedApp));
        return Map.of("app", normalizedApp, "status", "ACTIVE");
    }

    @GetMapping("/auth/apps/{app}/deletion-status")
    public Map<String, Object> deletionStatus(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("app") String app) {
        String normalizedApp = requireAllowedApp(app);
        long userId = currentUserId(authorization);
        AppMembership m = membershipRepository.find(userId, normalizedApp).orElse(null);
        String status = m == null ? "NONE" : m.status();
        boolean pending = "PENDING_DELETION".equalsIgnoreCase(status);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("app", normalizedApp);
        body.put("status", status);
        body.put("pendingDeletion", pending);
        return body;
    }

    private String requireAllowedApp(String app) {
        String normalized = app == null ? "" : app.trim().toLowerCase();
        if (!ALLOWED_APPS.contains(normalized)) {
            throw new AuthException(400, "APP_NOT_SUPPORTED", "不支持的应用");
        }
        return normalized;
    }

    private void verifySmsForUser(long userId, String phone, String smsCode) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(404, "USER_NOT_FOUND", "账号不存在"));
        String normalizedPhone = PhoneSupport.requireMainlandPhone(phone);
        String phoneHash = PhoneSupport.hashPhone(normalizedPhone, smsProperties.getPhoneHashPepper());
        if (!phoneHash.equals(user.phoneHash())) {
            throw new AuthException(400, "PHONE_MISMATCH", "手机号与账号注册手机号不匹配");
        }
        if (smsCode == null || smsCode.isBlank()) {
            throw new AuthException(400, "SMS_CODE_REQUIRED", "请输入验证码");
        }
        if (smsRateLimiter.isVerifyBlocked(SmsScene.VERIFICATION, phoneHash)) {
            throw new AuthException(429, "SMS_VERIFY_TOO_MANY", "验证码错误次数过多，请重新获取");
        }
        String providerOutId = smsRateLimiter.getPendingProviderOutId(SmsScene.VERIFICATION, phoneHash).orElse(null);
        MobileSmsAuthProvider.VerifyResult result = smsProvider.checkVerifyCode(
                new MobileSmsAuthProvider.VerifyRequest(normalizedPhone, smsCode, providerOutId, SmsScene.VERIFICATION));
        if (!result.success()) {
            smsRateLimiter.recordVerifyFailure(SmsScene.VERIFICATION, phoneHash);
            throw new AuthException(401, "SMS_CODE_INVALID", "验证码错误或已过期，请重新获取");
        }
        smsRateLimiter.clearVerifyFailures(SmsScene.VERIFICATION, phoneHash);
        smsRateLimiter.clearPendingCode(SmsScene.VERIFICATION, phoneHash);
    }

    private long currentUserId(String authorization) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        Object userId = claims.getClaim("user_id");
        if (userId == null) {
            throw new AuthException(401, "ACCESS_TOKEN_INVALID", "登录状态已失效，请重新登录");
        }
        return Long.parseLong(String.valueOf(userId));
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    public record DeletionRequest(String phone, String smsCode) {
    }
}
