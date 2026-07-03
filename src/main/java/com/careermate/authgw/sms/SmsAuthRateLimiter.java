package com.careermate.authgw.sms;

import java.time.Duration;
import java.util.Optional;
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
            throw new SmsException(429, "SMS_SEND_TOO_FREQUENT", "验证码已发送，请稍后再试");
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

    // 同一手机号在一个验证码有效期内允许的最大错误校验次数，达到即拒绝继续校验，防止对 6 位码暴力破解。
    private static final int VERIFY_FAIL_LIMIT = 5;

    /** 记录一次验证码校验失败（累加计数，随验证码 TTL 过期）。 */
    public void recordVerifyFailure(SmsScene scene, String phoneHash) {
        store.increment(key("authgw:sms:verify:fail", scene, phoneHash), CODE_TTL);
    }

    /**
     * 错误次数是否已达上限。达到后应在“调用云端短信服务商校验之前”直接拒绝——因为验证码由服务商在云端
     * 校验，清本地 pending 无法作废云端验证码，只能靠本地计数拦截继续尝试。
     */
    public boolean isVerifyBlocked(SmsScene scene, String phoneHash) {
        return store.getCounter(key("authgw:sms:verify:fail", scene, phoneHash)) >= VERIFY_FAIL_LIMIT;
    }

    /** 校验成功或重新下发验证码时清零错误计数。 */
    public void clearVerifyFailures(SmsScene scene, String phoneHash) {
        store.delete(key("authgw:sms:verify:fail", scene, phoneHash));
    }

    public void storePendingCode(SmsScene scene, String phoneHash, String codeHash, String providerOutId) {
        // 重新下发验证码时清零上一个码的错误计数，避免旧计数误伤新码。
        store.delete(key("authgw:sms:verify:fail", scene, phoneHash));
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

    public Optional<String> getPendingProviderOutId(SmsScene scene, String phoneHash) {
        return store.getValue(key("authgw:sms:pending:provider-out-id", scene, phoneHash));
    }

    public void clearPendingCode(SmsScene scene, String phoneHash) {
        store.delete(key("authgw:sms:pending:code", scene, phoneHash));
        store.delete(key("authgw:sms:pending:provider-out-id", scene, phoneHash));
    }

    private void assertUnderLimit(long count, int limit, String code, String label, String subject) {
        if (count >= limit) {
            log.warn("SMS rate limit {}, subject={}, count={}", label, subject, count);
            throw new SmsException(429, code, "验证码发送过于频繁，请稍后再试");
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
