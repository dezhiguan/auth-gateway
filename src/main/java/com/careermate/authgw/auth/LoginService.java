package com.careermate.authgw.auth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.sms.SmsCodeStore;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import java.time.Duration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class LoginService {

    private static final Duration FAIL_WINDOW = Duration.ofMinutes(5);
    private static final Duration LOCK_WINDOW = Duration.ofMinutes(30);

    private final AuthUserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TokenIssuer tokenIssuer;
    private final SmsCodeStore bucketStore;
    private final SmsAuthRateLimiter smsRateLimiter;
    private final MobileSmsAuthProvider smsProvider;
    private final SmsProperties smsProperties;
    private final JdbcTemplate jdbcTemplate;
    private final AuditLogService auditLogService;

    public LoginService(
            AuthUserRepository userRepository,
            PasswordHasher passwordHasher,
            TokenIssuer tokenIssuer,
            SmsCodeStore bucketStore,
            SmsAuthRateLimiter smsRateLimiter,
            MobileSmsAuthProvider smsProvider,
            SmsProperties smsProperties,
            JdbcTemplate jdbcTemplate,
            AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.tokenIssuer = tokenIssuer;
        this.bucketStore = bucketStore;
        this.smsRateLimiter = smsRateLimiter;
        this.smsProvider = smsProvider;
        this.smsProperties = smsProperties;
        this.jdbcTemplate = jdbcTemplate;
        this.auditLogService = auditLogService;
    }

    public TokenPair loginPassword(String account, String password, String targetAud, OAuthClient client) {
        String key = "authgw:login:password:fail:" + account;
        if (bucketStore.getValue(lockKey(account)).isPresent()) {
            throw new AuthException(423, "CAPTCHA_REQUIRED", "captcha required");
        }

        AuthUser user = userRepository.findByAccount(account)
                .orElseThrow(() -> fail(key, account));
        if (!"ACTIVE".equalsIgnoreCase(user.status()) || !passwordHasher.matches(password, user.passwordHash())) {
            throw fail(key, account);
        }
        bucketStore.delete(key);

        if ("ragforge-admin-api".equals(targetAud) && !"ADMIN".equalsIgnoreCase(user.platformRole())) {
            throw new AuthException(403, "PLATFORM_ROLE_DENIED", "platform role denied");
        }
        auditLogService.info("login.password.success", user.id(), client.clientId(), java.util.Map.of("target_aud", targetAud));
        return tokenIssuer.issueUserTokens(user, client, targetAud);
    }

    public TokenPair loginMobile(String phone, String code, String targetAud, OAuthClient client) {
        String normalizedPhone = PhoneSupport.requireMainlandPhone(phone);
        String phoneHash = PhoneSupport.hashPhone(normalizedPhone, smsProperties.getPhoneHashPepper());
        MobileSmsAuthProvider.VerifyResult verifyResult = smsProvider.checkVerifyCode(
                new MobileSmsAuthProvider.VerifyRequest(normalizedPhone, code, null, SmsScene.LOGIN));
        if (!verifyResult.success()) {
            throw new AuthException(401, "SMS_CODE_INVALID", "sms code is invalid or expired");
        }
        smsRateLimiter.clearPendingCode(SmsScene.LOGIN, phoneHash);

        AuthUser user = userRepository.findByPhoneHash(phoneHash)
                .orElseGet(() -> userRepository.createMobileUser(phoneHash));
        if (!"ACTIVE".equalsIgnoreCase(user.status())) {
            throw new AuthException(404, "USER_NOT_FOUND", "user not found");
        }

        if ("ragforge-admin-api".equals(targetAud) && !"ADMIN".equalsIgnoreCase(user.platformRole())) {
            throw new AuthException(403, "PLATFORM_ROLE_DENIED", "platform role denied");
        }
        auditLogService.info("login.mobile.success", user.id(), client.clientId(), java.util.Map.of("target_aud", targetAud, "phone", phone));
        return tokenIssuer.issueUserTokens(user, client, targetAud);
    }

    private AuthException fail(String key, String account) {
        long count = bucketStore.increment(key, FAIL_WINDOW);
        if (count >= 5) {
            bucketStore.setValue(lockKey(account), "1", LOCK_WINDOW);
            auditLogService.high("login.password.locked", null, null, java.util.Map.of("account", account));
            return new AuthException(423, "CAPTCHA_REQUIRED", "captcha required");
        }
        auditLogService.info("login.password.failed", null, null, java.util.Map.of("account", account, "failure_count", count));
        return new AuthException(401, "BAD_CREDENTIALS", "bad credentials");
    }

    private String lockKey(String account) {
        return "authgw:login:password:lock:" + account;
    }
}
