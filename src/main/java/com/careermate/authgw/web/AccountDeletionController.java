package com.careermate.authgw.web;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsException;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * 账号注销：申请进入 30 天冷静期 / 冷静期内撤销。
 *
 * <p>POST（申请注销）：需 Bearer token 识别用户 + phone+smsCode 二次验证。
 * DELETE（撤销注销）：账号已 PENDING_DELETION 无法登录，仅凭 phone+smsCode 识别用户。
 */
@RestController
public class AccountDeletionController {

    private final AccessTokenVerifier accessTokenVerifier;
    private final AuthUserRepository userRepository;
    private final MobileSmsAuthProvider smsProvider;
    private final SmsAuthRateLimiter smsRateLimiter;
    private final SmsProperties smsProperties;
    private final AuditLogService auditLogService;

    public AccountDeletionController(
            AccessTokenVerifier accessTokenVerifier,
            AuthUserRepository userRepository,
            MobileSmsAuthProvider smsProvider,
            SmsAuthRateLimiter smsRateLimiter,
            SmsProperties smsProperties,
            AuditLogService auditLogService) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.userRepository = userRepository;
        this.smsProvider = smsProvider;
        this.smsRateLimiter = smsRateLimiter;
        this.smsProperties = smsProperties;
        this.auditLogService = auditLogService;
    }

    /**
     * 申请注销。用户已登录（Bearer），通过 SMS OTP 二次验证后进入 30 天冷静期。
     * 请求体：{ phone, smsCode }，phone 须与账号注册手机号一致。
     */
    @PostMapping(value = "/auth/users/me/deletion-request", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> requestDeletion(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody DeletionRequest request) {
        long userId = currentUserId(authorization);
        verifySmsForUser(userId, request.phone(), request.smsCode());
        // 幂等：已在冷静期时保留首次的计划清理时间，重复申请不重置 30 天倒计时。
        java.time.Instant scheduledAt = userRepository.markPendingDeletion(userId);
        auditLogService.high("account.deletion.requested", userId, null, Map.of());
        return Map.of("deletionScheduledAt", scheduledAt.toString());
    }

    /**
     * 查询当前账号的注销状态。仅校验 Bearer 签名，不要求 ACTIVE，
     * 使 PENDING_DELETION 用户仍能读到自己的注销状态以在设置页展示"撤销注销"入口。
     */
    @GetMapping("/auth/users/me/deletion-status")
    public Map<String, Object> deletionStatus(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        long userId = currentUserId(authorization);
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(404, "USER_NOT_FOUND", "账号不存在"));
        boolean pending = "PENDING_DELETION".equalsIgnoreCase(user.status());
        java.time.Instant scheduledAt = pending ? userRepository.getDeletionScheduledAt(userId) : null;
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("status", user.status());
        body.put("pendingDeletion", pending);
        body.put("deletionScheduledAt", scheduledAt != null ? scheduledAt.toString() : null);
        return body;
    }

    /**
     * 撤销注销（冷静期内）。仅凭 Bearer token 识别用户即可撤销，无需短信二次验证——
     * 申请注销后不吊销当前会话，用户在设置页仍处登录态，可一键撤销（与 CareerMate 撤销体验一致）。
     */
    @DeleteMapping("/auth/users/me/deletion-request")
    public Map<String, Object> cancelDeletion(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        long userId = currentUserId(authorization);
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(404, "USER_NOT_FOUND", "账号不存在"));
        if (!"PENDING_DELETION".equalsIgnoreCase(user.status())) {
            throw new AuthException(400, "NOT_PENDING_DELETION", "账号当前未处于注销冷静期");
        }
        userRepository.cancelDeletion(userId);
        auditLogService.info("account.deletion.cancelled", userId, null, Map.of());
        return Map.of("status", "ACTIVE");
    }

    /** 验证用户（通过 Bearer token 识别）的手机号 SMS OTP。 */
    private void verifySmsForUser(long userId, String phone, String smsCode) {
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(404, "USER_NOT_FOUND", "账号不存在"));
        String normalizedPhone = PhoneSupport.requireMainlandPhone(phone);
        String phoneHash = PhoneSupport.hashPhone(normalizedPhone, smsProperties.getPhoneHashPepper());
        if (!phoneHash.equals(user.phoneHash())) {
            throw new AuthException(400, "PHONE_MISMATCH", "手机号与账号注册手机号不匹配");
        }
        verifySmsForPhone(normalizedPhone, phoneHash, smsCode);
    }

    private void verifySmsForPhone(String normalizedPhone, String phoneHash, String smsCode) {
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
        if (userId == null) throw new AuthException(401, "USER_ID_MISSING", "token 中缺少 user_id");
        return ((Number) userId).longValue();
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    /** 手机号格式非法（含缺失/空/畸形）由此返回友好 400，而非落到框架 500。 */
    @ExceptionHandler(SmsException.class)
    public ResponseEntity<Map<String, Object>> handleSmsException(SmsException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    public record DeletionRequest(String phone, String smsCode) {}
}
