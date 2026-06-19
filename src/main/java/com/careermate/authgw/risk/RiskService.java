package com.careermate.authgw.risk;

import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsCodeStore;
import java.time.Duration;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class RiskService {

    private static final Duration FAIL_WINDOW = Duration.ofMinutes(5);
    private static final Duration LOCK_WINDOW = Duration.ofMinutes(30);
    private static final Duration IP_WINDOW = Duration.ofMinutes(1);

    private final SmsCodeStore store;

    public RiskService(SmsCodeStore store) {
        this.store = store;
    }

    public RiskDecision recordLoginFailure(String account, String ip) {
        String accountKey = "authgw:risk:login:fail:" + account;
        String lockKey = "authgw:risk:login:lock:" + account;
        long failures = store.increment(accountKey, FAIL_WINDOW);
        boolean captchaRequired = failures >= 5;
        if (captchaRequired) {
            store.setValue(lockKey, "1", LOCK_WINDOW);
        }
        long ipFailures = store.increment("authgw:risk:ip:" + PhoneSupport.normalizeIp(ip), IP_WINDOW);
        boolean ipLimited = ipFailures > 30;
        return new RiskDecision(captchaRequired, ipLimited, store.getRemainingTtlSeconds(lockKey).orElse(0L));
    }

    public Map<String, Object> locationWarning(long userId, String lastRegion, String currentRegion) {
        boolean unusual = lastRegion != null && currentRegion != null && !lastRegion.equalsIgnoreCase(currentRegion);
        return Map.of("user_id", userId, "unusual_location", unusual);
    }

    public record RiskDecision(boolean captchaRequired, boolean ipLimited, long lockTtlSeconds) {
    }
}
