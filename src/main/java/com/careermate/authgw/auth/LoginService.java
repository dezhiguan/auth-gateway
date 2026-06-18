package com.careermate.authgw.auth;

import com.careermate.authgw.sms.SmsCodeStore;
import java.time.Duration;
import org.springframework.stereotype.Service;

@Service
public class LoginService {

    private static final Duration FAIL_WINDOW = Duration.ofMinutes(5);
    private static final Duration LOCK_WINDOW = Duration.ofMinutes(30);

    private final AuthUserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TokenIssuer tokenIssuer;
    private final SmsCodeStore bucketStore;

    public LoginService(
            AuthUserRepository userRepository,
            PasswordHasher passwordHasher,
            TokenIssuer tokenIssuer,
            SmsCodeStore bucketStore) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.tokenIssuer = tokenIssuer;
        this.bucketStore = bucketStore;
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
        return tokenIssuer.issueUserTokens(user, client, targetAud);
    }

    private AuthException fail(String key, String account) {
        long count = bucketStore.increment(key, FAIL_WINDOW);
        if (count >= 5) {
            bucketStore.setValue(lockKey(account), "1", LOCK_WINDOW);
            return new AuthException(423, "CAPTCHA_REQUIRED", "captcha required");
        }
        return new AuthException(401, "BAD_CREDENTIALS", "bad credentials");
    }

    private String lockKey(String account) {
        return "authgw:login:password:lock:" + account;
    }
}
