package com.careermate.authgw.auth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * 注册 / 账号补全。手机号为全局关联键：
 * - 手机号不存在 → 新建账号。
 * - 手机号已存在（如仅在 CareerMate 注册过）→ 仅补全为空的字段(enrich)，不新建、不覆盖。
 */
@Service
public class RegistrationService {

    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9_]{3,32}$");
    private static final Set<String> APPS = Set.of("careermate", "ragforge");

    private final AuthUserRepository userRepository;
    private final MembershipRepository membershipRepository;
    private final PasswordHasher passwordHasher;
    private final MobileSmsAuthProvider smsProvider;
    private final SmsAuthRateLimiter smsRateLimiter;
    private final SmsProperties smsProperties;
    private final AuditLogService auditLogService;

    public RegistrationService(
            AuthUserRepository userRepository,
            MembershipRepository membershipRepository,
            PasswordHasher passwordHasher,
            MobileSmsAuthProvider smsProvider,
            SmsAuthRateLimiter smsRateLimiter,
            SmsProperties smsProperties,
            AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.passwordHasher = passwordHasher;
        this.smsProvider = smsProvider;
        this.smsRateLimiter = smsRateLimiter;
        this.smsProperties = smsProperties;
        this.auditLogService = auditLogService;
    }

    public RegisterResult register(String phone, String smsCode, String username, String email, String rawPassword, String app) {
        String normalizedApp = normalizeApp(app);
        String pepper = smsProperties.getPhoneHashPepper();
        String normalizedPhone = PhoneSupport.requireMainlandPhone(phone);
        String phoneHash = PhoneSupport.hashPhone(normalizedPhone, pepper);

        MobileSmsAuthProvider.VerifyResult verify = smsProvider.checkVerifyCode(
                new MobileSmsAuthProvider.VerifyRequest(normalizedPhone, smsCode, null, SmsScene.REGISTER));
        if (!verify.success()) {
            throw new AuthException(401, "SMS_CODE_INVALID", "验证码错误或已过期，请重新获取");
        }
        smsRateLimiter.clearPendingCode(SmsScene.REGISTER, phoneHash);

        String normUsername = StringUtils.hasText(username) ? username.trim() : null;
        if (normUsername != null) {
            validateUsername(normUsername);
        }
        String emailHash = null;
        if (StringUtils.hasText(email)) {
            emailHash = EmailSupport.hashEmail(EmailSupport.requireValidEmail(email), pepper);
        }
        String passwordHash = null;
        if (StringUtils.hasText(rawPassword)) {
            passwordHash = passwordHasher.hash(validatePassword(rawPassword));
        }

        try {
            Optional<AuthUser> existing = userRepository.findByPhoneHash(phoneHash);
            long userId;
            boolean linked;
            if (existing.isPresent()) {
                AuthUser u = existing.get();
                userId = u.id();
                linked = true;
                if (normUsername != null && u.username() == null) {
                    ensureUsernameAvailable(normUsername, userId);
                }
                if (emailHash != null && u.emailHash() == null) {
                    ensureEmailAvailable(emailHash, userId);
                }
                userRepository.enrich(
                        userId,
                        u.emailHash() == null ? emailHash : null,
                        u.username() == null ? normUsername : null,
                        u.passwordHash() == null ? passwordHash : null);
            } else {
                if (normUsername != null) {
                    ensureUsernameAvailable(normUsername, -1);
                }
                if (emailHash != null) {
                    ensureEmailAvailable(emailHash, -1);
                }
                AuthUser created = userRepository.createFullUser(phoneHash, emailHash, normUsername, passwordHash);
                userId = created.id();
                linked = false;
            }
            membershipRepository.ensureMembership(userId, normalizedApp, "USER");
            auditLogService.info("register.success", userId, null,
                    Map.of("app", normalizedApp, "linked", linked));
            return new RegisterResult(userId, linked);
        } catch (DuplicateKeyException ex) {
            // 唯一索引兜底（并发等场景）
            throw new AuthException(409, "ACCOUNT_IDENTIFIER_TAKEN", "用户名或邮箱已被占用");
        }
    }

    private void ensureUsernameAvailable(String username, long selfId) {
        userRepository.findByAccount(username)
                .filter(u -> u.id() != selfId)
                .ifPresent(u -> {
                    throw new AuthException(409, "USERNAME_TAKEN", "该用户名已被占用");
                });
    }

    private void ensureEmailAvailable(String emailHash, long selfId) {
        userRepository.findByEmailHash(emailHash)
                .filter(u -> u.id() != selfId)
                .ifPresent(u -> {
                    throw new AuthException(409, "EMAIL_TAKEN", "该邮箱已注册");
                });
    }

    private void validateUsername(String username) {
        if (!USERNAME.matcher(username).matches()) {
            throw new AuthException(400, "USERNAME_FORMAT_INVALID", "用户名需为 3-32 位字母、数字或下划线");
        }
    }

    private String validatePassword(String password) {
        if (password.length() < 8 || password.length() > 64) {
            throw new AuthException(400, "PASSWORD_WEAK", "密码长度需为 8-64 位");
        }
        boolean hasLetter = password.chars().anyMatch(Character::isLetter);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        if (!hasLetter || !hasDigit) {
            throw new AuthException(400, "PASSWORD_WEAK", "密码需同时包含字母和数字");
        }
        return password;
    }

    private String normalizeApp(String app) {
        String normalized = app == null ? "" : app.trim().toLowerCase();
        if (!APPS.contains(normalized)) {
            throw new AuthException(400, "APP_INVALID", "未知的应用来源");
        }
        return normalized;
    }

    public record RegisterResult(long userId, boolean linked) {
    }
}
