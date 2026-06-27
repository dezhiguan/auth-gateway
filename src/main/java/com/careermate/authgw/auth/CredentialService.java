package com.careermate.authgw.auth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.events.EventPublisher;
import com.careermate.authgw.sms.SmsProperties;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * 凭证管理：设密码 / 绑邮箱 / 设登录用户名。供 RAG 安全中心代理调用。
 * 凭证统一落网关 auth_users（不在各 App 本地保存）。
 */
@Service
public class CredentialService {

    // 允许中文（CJK 基本汉字）、字母、数字、下划线；中文名可短至 2 字，故下限取 2。
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9_\\u4e00-\\u9fa5]{2,32}$");

    private final AuthUserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final JdbcTemplate jdbcTemplate;
    private final EventPublisher eventPublisher;
    private final AuditLogService auditLogService;
    private final SmsProperties smsProperties;

    public CredentialService(
            AuthUserRepository userRepository,
            PasswordHasher passwordHasher,
            JdbcTemplate jdbcTemplate,
            EventPublisher eventPublisher,
            AuditLogService auditLogService,
            SmsProperties smsProperties) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.jdbcTemplate = jdbcTemplate;
        this.eventPublisher = eventPublisher;
        this.auditLogService = auditLogService;
        this.smsProperties = smsProperties;
    }

    /** 设置/修改密码。已有密码必须校验旧密码；变更后撤销该用户全部会话并发事件。 */
    @Transactional
    public void setPassword(long userId, String oldPassword, String newPassword) {
        AuthUser user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(404, "USER_NOT_FOUND", "账号不存在"));
        if (StringUtils.hasText(user.passwordHash())) {
            if (!StringUtils.hasText(oldPassword) || !passwordHasher.matches(oldPassword, user.passwordHash())) {
                throw new AuthException(400, "OLD_PASSWORD_INVALID", "原密码不正确");
            }
        }
        validatePassword(newPassword);
        userRepository.updatePasswordAndIncrementSessionVersion(userId, passwordHasher.hash(newPassword));
        revokeAllSessions(userId);
        eventPublisher.publish("user.password.changed", Map.of("user_id", userId));
        auditLogService.high("user.password.changed", userId, null, Map.of("via", "credential"));
    }

    /** 绑定/更换邮箱。已有密码时需密码二次确认；邮箱全局唯一。 */
    @Transactional
    public void bindEmail(long userId, String email, String password) {
        AuthUser user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(404, "USER_NOT_FOUND", "账号不存在"));
        if (StringUtils.hasText(user.passwordHash())) {
            if (!StringUtils.hasText(password) || !passwordHasher.matches(password, user.passwordHash())) {
                throw new AuthException(400, "PASSWORD_INVALID", "密码不正确");
            }
        }
        String emailHash = EmailSupport.hashEmail(
                EmailSupport.requireValidEmail(email), smsProperties.getPhoneHashPepper());
        userRepository.findByEmailHash(emailHash)
                .filter(u -> u.id() != userId)
                .ifPresent(u -> {
                    throw new AuthException(409, "EMAIL_TAKEN", "该邮箱已被占用");
                });
        try {
            userRepository.updateEmailHash(userId, emailHash);
        } catch (DuplicateKeyException ex) {
            throw new AuthException(409, "EMAIL_TAKEN", "该邮箱已被占用");
        }
        auditLogService.info("user.email.bound", userId, null, Map.of());
    }

    /** 设置/修改登录用户名，全局唯一。 */
    @Transactional
    public void setUsername(long userId, String username) {
        String normalized = username == null ? "" : username.trim();
        if (!USERNAME.matcher(normalized).matches()) {
            throw new AuthException(400, "USERNAME_FORMAT_INVALID", "用户名需为 2-32 位中文、字母、数字或下划线");
        }
        userRepository.findByAccount(normalized)
                .filter(u -> u.id() != userId)
                .ifPresent(u -> {
                    throw new AuthException(409, "USERNAME_TAKEN", "该用户名已被占用");
                });
        try {
            userRepository.updateUsername(userId, normalized);
        } catch (DuplicateKeyException ex) {
            throw new AuthException(409, "USERNAME_TAKEN", "该用户名已被占用");
        }
        auditLogService.info("user.username.set", userId, null, Map.of());
    }

    private void revokeAllSessions(long userId) {
        jdbcTemplate.update("""
                        UPDATE auth_sessions
                        SET revoked_at = COALESCE(revoked_at, now())
                        WHERE user_id = ?
                        """,
                userId);
        jdbcTemplate.update("""
                        UPDATE refresh_tokens
                        SET revoked_at = COALESCE(revoked_at, now())
                        WHERE session_id IN (SELECT session_id FROM auth_sessions WHERE user_id = ?)
                        """,
                userId);
    }

    private void validatePassword(String password) {
        if (!StringUtils.hasText(password) || password.length() < 8 || password.length() > 64) {
            throw new AuthException(400, "PASSWORD_WEAK", "密码长度需为 8-64 位");
        }
        boolean hasLetter = password.chars().anyMatch(Character::isLetter);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        if (!hasLetter || !hasDigit) {
            throw new AuthException(400, "PASSWORD_WEAK", "密码需同时包含字母和数字");
        }
    }
}
