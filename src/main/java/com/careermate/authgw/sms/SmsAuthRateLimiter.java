package com.careermate.authgw.sms;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SmsAuthRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(SmsAuthRateLimiter.class);

    private static final Duration ONE_MINUTE = Duration.ofMinutes(1);
    private static final Duration ONE_DAY = Duration.ofDays(1);
    private static final Duration CODE_TTL = Duration.ofMinutes(5);

    private static final int PHONE_DAY_SEND_LIMIT = 10;
    private static final int IP_MINUTE_SEND_LIMIT = 30;

    private final SmsCodeStore store;

    public SmsAuthRateLimiter(SmsCodeStore store) {
        this.store = store;
    }

    public void checkSendAllowed(SmsScene scene, String phoneHash, String ipHash, String maskedPhone) {
        if (store.getValue(key("authgw:sms:send:cooldown", scene, phoneHash)).isPresent()) {
            log.warn("SMS send cooldown, phone={}", maskedPhone);
            throw new SmsException(429, "SMS_SEND_TOO_FREQUENT", "sms send too frequent");
        }
        assertUnderLimit(store.getCounter(key("authgw:sms:send:day", scene, phoneHash)),
                PHONE_DAY_SEND_LIMIT, "SMS_PHONE_DAY_LIMITED", "send phone day", maskedPhone);
        assertUnderLimit(store.getCounter(key("authgw:sms:send:ip:minute", scene, ipHash)),
                IP_MINUTE_SEND_LIMIT, "SMS_IP_MINUTE_LIMITED", "send ip minute", ipHash);
    }

    public void recordSend(SmsScene scene, String phoneHash, String ipHash) {
        store.setValue(key("authgw:sms:send:cooldown", scene, phoneHash), "1", ONE_MINUTE);
        store.increment(key("authgw:sms:send:day", scene, phoneHash), ONE_DAY);
        store.increment(key("authgw:sms:send:ip:minute", scene, ipHash), ONE_MINUTE);
    }

    public long sendCooldownRemainingSeconds(SmsScene scene, String phoneHash) {
        return store.getRemainingTtlSeconds(key("authgw:sms:send:cooldown", scene, phoneHash)).orElse(0L);
    }

    public void storePendingCode(SmsScene scene, String phoneHash, String codeHash, String providerOutId) {
        store.setValue(key("authgw:sms:pending:code", scene, phoneHash), codeHash, CODE_TTL);
        String outIdKey = key("authgw:sms:pending:provider-out-id", scene, phoneHash);
        if (providerOutId == null || providerOutId.isBlank()) {
            store.delete(outIdKey);
        } else {
            store.setValue(outIdKey, providerOutId, CODE_TTL);
        }
    }

    public boolean matchesPendingCode(SmsScene scene, String phoneHash, String codeHash) {
        return store.getValue(key("authgw:sms:pending:code", scene, phoneHash))
                .map(value -> value.equals(codeHash))
                .orElse(false);
    }

    public void clearPendingCode(SmsScene scene, String phoneHash) {
        store.delete(key("authgw:sms:pending:code", scene, phoneHash));
        store.delete(key("authgw:sms:pending:provider-out-id", scene, phoneHash));
    }

    private void assertUnderLimit(long count, int limit, String code, String label, String subject) {
        if (count >= limit) {
            log.warn("SMS rate limit {}, subject={}, count={}", label, subject, count);
            throw new SmsException(429, code, "sms send limited");
        }
    }

    private String key(String prefix, SmsScene scene, String... parts) {
        StringBuilder builder = new StringBuilder(prefix).append(':').append(scene.value());
        for (String part : parts) {
            builder.append(':').append(part);
        }
        return builder.toString();
    }
}
