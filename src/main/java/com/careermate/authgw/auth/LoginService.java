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
    private final MembershipRepository membershipRepository;
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
            MembershipRepository membershipRepository,
            PasswordHasher passwordHasher,
            TokenIssuer tokenIssuer,
            SmsCodeStore bucketStore,
            SmsAuthRateLimiter smsRateLimiter,
            MobileSmsAuthProvider smsProvider,
            SmsProperties smsProperties,
            JdbcTemplate jdbcTemplate,
            AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
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
            throw new AuthException(423, "CAPTCHA_REQUIRED", "登录失败次数较多，请稍后再试");
        }

        AuthUser user = findPasswordLoginUser(account)
                .orElseThrow(() -> fail(key, account));
        if (!"ACTIVE".equalsIgnoreCase(user.status()) || !passwordHasher.matches(password, user.passwordHash())) {
            throw fail(key, account);
        }
        bucketStore.delete(key);

        enforceRagForgeAccess(targetAud, user);
        auditLogService.info("login.password.success", user.id(), client.clientId(), java.util.Map.of("target_aud", targetAud));
        return tokenIssuer.issueUserTokens(user, client, targetAud);
    }

    public TokenPair loginMobile(String phone, String code, String targetAud, OAuthClient client) {
        String normalizedPhone = PhoneSupport.requireMainlandPhone(phone);
        String phoneHash = PhoneSupport.hashPhone(normalizedPhone, smsProperties.getPhoneHashPepper());
        String providerOutId = smsRateLimiter.getPendingProviderOutId(SmsScene.LOGIN, phoneHash).orElse(null);
        MobileSmsAuthProvider.VerifyResult verifyResult = smsProvider.checkVerifyCode(
                new MobileSmsAuthProvider.VerifyRequest(normalizedPhone, code, providerOutId, SmsScene.LOGIN));
        if (!verifyResult.success()) {
            throw new AuthException(401, "SMS_CODE_INVALID", "验证码错误或已过期，请重新获取");
        }
        smsRateLimiter.clearPendingCode(SmsScene.LOGIN, phoneHash);

        AuthUser user = userRepository.findByPhoneHash(phoneHash)
                .orElseGet(() -> userRepository.createMobileUser(phoneHash));
        if (!"ACTIVE".equalsIgnoreCase(user.status())) {
            throw new AuthException(404, "USER_NOT_FOUND", "账号不存在或已停用");
        }

        enforceRagForgeAccess(targetAud, user);
        auditLogService.info("login.mobile.success", user.id(), client.clientId(), java.util.Map.of("target_aud", targetAud, "phone", phone));
        return tokenIssuer.issueUserTokens(user, client, targetAud);
    }

    /**
     * RAG 准入：登录目标受众为 ragforge-admin-api 时，要求用户拥有 ragforge 应用准入。
     * 自助注册会写入该准入；CareerMate-only 用户未在 RAG 注册则被拒。
     */
    public void enforceRagForgeAccess(String targetAud, AuthUser user) {
        if (!"ragforge-admin-api".equals(targetAud)) {
            return;
        }
        if (membershipRepository.find(user.id(), "ragforge").isEmpty()) {
            throw new AuthException(403, "RAGFORGE_ACCESS_DENIED", "请先在 RAGForge 注册或由管理员开通访问权限");
        }
    }

    private java.util.Optional<AuthUser> findPasswordLoginUser(String account) {
        // 1) 手机号
        try {
            String phone = PhoneSupport.requireMainlandPhone(account);
            String phoneHash = PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper());
            java.util.Optional<AuthUser> byPhone = userRepository.findByPhoneHash(phoneHash);
            if (byPhone.isPresent()) {
                return byPhone;
            }
        } catch (RuntimeException ignored) {
            // 非手机号，继续尝试邮箱/用户名
        }
        // 2) 邮箱
        if (EmailSupport.isValidEmail(account)) {
            String emailHash = EmailSupport.hashEmail(account, smsProperties.getPhoneHashPepper());
            java.util.Optional<AuthUser> byEmail = userRepository.findByEmailHash(emailHash);
            if (byEmail.isPresent()) {
                return byEmail;
            }
        }
        // 3) 用户名
        return userRepository.findByAccount(account);
    }

    private AuthException fail(String key, String account) {
        long count = bucketStore.increment(key, FAIL_WINDOW);
        if (count >= 5) {
            bucketStore.setValue(lockKey(account), "1", LOCK_WINDOW);
            auditLogService.high("login.password.locked", null, null, java.util.Map.of("account", account));
            return new AuthException(423, "CAPTCHA_REQUIRED", "登录失败次数较多，请稍后再试");
        }
        auditLogService.info("login.password.failed", null, null, java.util.Map.of("account", account, "failure_count", count));
        return new AuthException(401, "BAD_CREDENTIALS", "账号或密码不正确");
    }

    private String lockKey(String account) {
        return "authgw:login:password:lock:" + account;
    }
}
