package com.careermate.authgw.auth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.crypto.JwtSigner;
import com.careermate.authgw.crypto.JwksProvider;
import com.careermate.authgw.events.EventPublisher;
import com.careermate.authgw.sms.MobileSmsAuthProvider;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsAuthRateLimiter;
import com.careermate.authgw.sms.SmsCodeStore;
import com.careermate.authgw.sms.SmsException;
import com.careermate.authgw.sms.SmsProperties;
import com.careermate.authgw.sms.SmsScene;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class PasswordResetService {

    public static final String ENUMERATION_SAFE_MASKED_PHONE = "***********";

    private static final String RESET_TICKET_AUDIENCE = "auth-gateway:password-reset";
    private static final Duration RESET_TICKET_TTL = Duration.ofMinutes(5);
    private static final Duration CONFIRM_LOCK_TTL = Duration.ofMinutes(30);

    private final AuthUserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TokenIssuer tokenIssuer;
    private final JwtSigner jwtSigner;
    private final JwksProvider jwksProvider;
    private final JdbcTemplate jdbcTemplate;
    private final SmsProperties smsProperties;
    private final SmsCodeStore codeStore;
    private final SmsAuthRateLimiter smsRateLimiter;
    private final MobileSmsAuthProvider smsProvider;
    private final AuthProperties authProperties;
    private final EventPublisher eventPublisher;
    private final AuditLogService auditLogService;

    public PasswordResetService(
            AuthUserRepository userRepository,
            PasswordHasher passwordHasher,
            TokenIssuer tokenIssuer,
            JwtSigner jwtSigner,
            JwksProvider jwksProvider,
            JdbcTemplate jdbcTemplate,
            SmsProperties smsProperties,
            SmsCodeStore codeStore,
            SmsAuthRateLimiter smsRateLimiter,
            MobileSmsAuthProvider smsProvider,
            AuthProperties authProperties,
            EventPublisher eventPublisher,
            AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.tokenIssuer = tokenIssuer;
        this.jwtSigner = jwtSigner;
        this.jwksProvider = jwksProvider;
        this.jdbcTemplate = jdbcTemplate;
        this.smsProperties = smsProperties;
        this.codeStore = codeStore;
        this.smsRateLimiter = smsRateLimiter;
        this.smsProvider = smsProvider;
        this.authProperties = authProperties;
        this.eventPublisher = eventPublisher;
        this.auditLogService = auditLogService;
    }

    public ResetInitResult init(String account, String phone) {
        findResettableUser(account).ifPresent(user -> {
            String normalizedPhone = normalizeOptionalPhone(phone);
            if (StringUtils.hasText(user.phoneHash())
                    && StringUtils.hasText(normalizedPhone)
                    && user.phoneHash().equals(PhoneSupport.hashPhone(normalizedPhone, smsProperties.getPhoneHashPepper()))) {
                String code = resolveCode();
                String phoneHash = PhoneSupport.hashPhone(normalizedPhone, smsProperties.getPhoneHashPepper());
                String ipHash = PhoneSupport.hashIp("password-reset", smsProperties.getPhoneHashPepper());
                smsRateLimiter.checkSendAllowed(SmsScene.RESET, phoneHash, ipHash, PhoneSupport.maskPhone(normalizedPhone));
                try {
                    smsProvider.sendVerifyCode(new MobileSmsAuthProvider.SendRequest(normalizedPhone, SmsScene.RESET, code));
                    smsRateLimiter.recordSend(SmsScene.RESET, phoneHash, ipHash);
                } catch (SmsException ex) {
                    throw ex;
                } catch (RuntimeException ex) {
                    throw new AuthException(502, "SMS_PROVIDER_ERROR", "短信服务暂时不可用，请稍后再试");
                }
            }
        });
        return new ResetInitResult(ENUMERATION_SAFE_MASKED_PHONE, true);
    }

    @Transactional
    public String verify(String account, String phone, String code) {
        AuthUser user = findResettableUser(account)
                .orElseThrow(() -> new AuthException(401, "SMS_CODE_INVALID", "验证码错误或已过期，请重新获取"));
        String confirmLockKey = confirmLockKey(user.id());
        if (codeStore.getValue(confirmLockKey).isPresent()) {
            throw new AuthException(429, "PASSWORD_RESET_LOCKED", "操作过于频繁，请稍后再试");
        }

        String normalizedPhone = normalizeOptionalPhone(phone);
        if (!StringUtils.hasText(normalizedPhone)
                || !user.phoneHash().equals(PhoneSupport.hashPhone(normalizedPhone, smsProperties.getPhoneHashPepper()))) {
            recordConfirmFailure(user.id());
            throw new AuthException(401, "SMS_CODE_INVALID", "验证码错误或已过期，请重新获取");
        }
        MobileSmsAuthProvider.VerifyResult verifyResult = smsProvider.checkVerifyCode(
                new MobileSmsAuthProvider.VerifyRequest(normalizedPhone, code, null, SmsScene.RESET));
        if (!verifyResult.success()) {
            recordConfirmFailure(user.id());
            throw new AuthException(401, "SMS_CODE_INVALID", "验证码错误或已过期，请重新获取");
        }
        codeStore.delete(confirmFailKey(user.id()));
        return issueResetTicket(user);
    }

    @Transactional
    public TokenPair confirm(String resetTicket, String newPassword, OAuthClient client, String targetAud) {
        JWTClaimsSet claims = verifyResetTicket(resetTicket);
        long userId = Long.parseLong(String.valueOf(claims.getClaim("user_id")));
        if (codeStore.getValue(confirmLockKey(userId)).isPresent()) {
            throw new AuthException(429, "PASSWORD_RESET_LOCKED", "操作过于频繁，请稍后再试");
        }
        if (!StringUtils.hasText(newPassword) || newPassword.length() < 8) {
            recordConfirmFailure(userId);
            throw new AuthException(400, "PASSWORD_WEAK", "密码至少需要 8 位");
        }
        AuthUser user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(401, "USER_NOT_FOUND", "user not found"));
        LoginService.enforceRagForgeAdminAccess(targetAud, user);

        userRepository.updatePasswordAndIncrementSessionVersion(userId, passwordHasher.hash(newPassword));
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
        codeStore.delete(confirmFailKey(userId));
        eventPublisher.publish("user.password.changed", Map.of("user_id", userId));
        auditLogService.high("user.password.changed", userId, client.clientId(), Map.of("reset_ticket", resetTicket));

        user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(401, "USER_NOT_FOUND", "user not found"));
        return tokenIssuer.issueUserTokens(user, client, targetAud);
    }

    private Optional<AuthUser> findResettableUser(String account) {
        Optional<AuthUser> byPhone = findByPhoneAccount(account);
        Optional<AuthUser> user = byPhone.isPresent() ? byPhone : userRepository.findByAccount(account);
        return user.filter(candidate -> "ACTIVE".equalsIgnoreCase(candidate.status())
                && StringUtils.hasText(candidate.phoneHash()));
    }

    private Optional<AuthUser> findByPhoneAccount(String account) {
        try {
            String phone = PhoneSupport.requireMainlandPhone(account);
            return userRepository.findByPhoneHash(PhoneSupport.hashPhone(phone, smsProperties.getPhoneHashPepper()));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    private String normalizeOptionalPhone(String phone) {
        try {
            return PhoneSupport.requireMainlandPhone(phone);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private String issueResetTicket(AuthUser user) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(authProperties.getIssuer())
                .audience(RESET_TICKET_AUDIENCE)
                .subject("password-reset:user:" + user.id())
                .jwtID("prt_" + UUID.randomUUID())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(RESET_TICKET_TTL)))
                .claim("scope", "set_password")
                .claim("user_id", user.id())
                .claim("session_version", user.sessionVersion())
                .build();
        return jwtSigner.sign(claims);
    }

    private JWTClaimsSet verifyResetTicket(String resetTicket) {
        try {
            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            JWSKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(
                    JWSAlgorithm.RS256,
                    new ImmutableJWKSet<>(jwksProvider.publicJwkSet()));
            processor.setJWSKeySelector(selector);
            JWTClaimsSet claims = processor.process(resetTicket, null);
            Date expiration = claims.getExpirationTime();
            if (!authProperties.getIssuer().equals(claims.getIssuer())
                    || expiration == null
                    || expiration.before(new Date())
                    || !claims.getAudience().contains(RESET_TICKET_AUDIENCE)
                    || !"set_password".equals(claims.getStringClaim("scope"))) {
                throw new AuthException(401, "RESET_TICKET_INVALID", "reset ticket is invalid");
            }
            AuthUser user = userRepository.findById(Long.parseLong(String.valueOf(claims.getClaim("user_id"))))
                    .orElseThrow(() -> new AuthException(401, "RESET_TICKET_INVALID", "reset ticket is invalid"));
            long ticketSessionVersion = Long.parseLong(String.valueOf(claims.getClaim("session_version")));
            if (user.sessionVersion() != ticketSessionVersion) {
                throw new AuthException(401, "RESET_TICKET_INVALID", "reset ticket is invalid");
            }
            return claims;
        } catch (AuthException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AuthException(401, "RESET_TICKET_INVALID", "reset ticket is invalid");
        }
    }

    private void recordConfirmFailure(long userId) {
        long count = codeStore.increment(confirmFailKey(userId), CONFIRM_LOCK_TTL);
        if (count >= 5) {
            codeStore.setValue(confirmLockKey(userId), "1", CONFIRM_LOCK_TTL);
        }
    }

    private String resolveCode() {
        if (StringUtils.hasText(smsProperties.getMockCode())) {
            return smsProperties.getMockCode();
        }
        return PhoneSupport.generateNumericCode(6);
    }

    private String confirmFailKey(long userId) {
        return "authgw:password-reset:confirm:fail:" + userId;
    }

    private String confirmLockKey(long userId) {
        return "authgw:password-reset:confirm:lock:" + userId;
    }

    public record ResetInitResult(String maskedPhone, boolean ticketRequired) {
    }
}
