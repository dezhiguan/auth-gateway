package com.careermate.authgw.sms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SmsAuthRateLimiterTest {

    @Mock SmsCodeStore store;

    @Test
    void checkSendAllowedRejectsCooldown() {
        when(store.getValue("authgw:sms:send:cooldown:login:phone")).thenReturn(Optional.of("1"));

        assertThatThrownBy(() -> limiter().checkSendAllowed(SmsScene.LOGIN, "phone", "ip", "138****0000"))
                .isInstanceOfSatisfying(SmsException.class, ex -> {
                    assertThat(ex.status()).isEqualTo(429);
                    assertThat(ex.code()).isEqualTo("SMS_SEND_TOO_FREQUENT");
                });
    }

    @Test
    void checkSendAllowedRejectsPhoneDayLimit() {
        when(store.getValue("authgw:sms:send:cooldown:reset:phone")).thenReturn(Optional.empty());
        when(store.getCounter("authgw:sms:send:day:reset:phone")).thenReturn(10L);

        assertThatThrownBy(() -> limiter().checkSendAllowed(SmsScene.RESET, "phone", "ip", "138****0000"))
                .isInstanceOfSatisfying(SmsException.class, ex -> assertThat(ex.code()).isEqualTo("SMS_PHONE_DAY_LIMITED"));
    }

    @Test
    void recordSendWritesCooldownAndCounters() {
        limiter().recordSend(SmsScene.REGISTER, "phone", "ip");

        verify(store).setValue("authgw:sms:send:cooldown:register:phone", "1", Duration.ofMinutes(1));
        verify(store).increment("authgw:sms:send:day:register:phone", Duration.ofDays(1));
        verify(store).increment("authgw:sms:send:ip:minute:register:ip", Duration.ofMinutes(1));
    }

    @Test
    void storePendingCodeDeletesBlankProviderOutIdAndMatchesCode() {
        SmsAuthRateLimiter limiter = limiter();
        limiter.storePendingCode(SmsScene.LOGIN, "phone", "code-hash", " ");
        verify(store).setValue("authgw:sms:pending:code:login:phone", "code-hash", Duration.ofMinutes(5));
        verify(store).delete("authgw:sms:pending:provider-out-id:login:phone");

        when(store.getValue("authgw:sms:pending:code:login:phone")).thenReturn(Optional.of("code-hash"));
        assertThat(limiter.matchesPendingCode(SmsScene.LOGIN, "phone", "code-hash")).isTrue();
        assertThat(limiter.matchesPendingCode(SmsScene.LOGIN, "phone", "bad")).isFalse();
    }

    @Test
    void clearPendingCodeDeletesBothKeys() {
        limiter().clearPendingCode(SmsScene.RESET, "phone");

        verify(store).delete("authgw:sms:pending:code:reset:phone");
        verify(store).delete("authgw:sms:pending:provider-out-id:reset:phone");
    }

    private SmsAuthRateLimiter limiter() {
        return new SmsAuthRateLimiter(store);
    }
}
