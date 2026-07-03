package com.careermate.authgw.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.careermate.authgw.sms.SmsCodeStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CaptchaServiceTest {

    private final InMemoryStore store = new InMemoryStore();
    private final CaptchaService service = new CaptchaService(store);

    @Test
    void generate_returnsChallengeAndPngDataUrl_andStoresCode() {
        CaptchaService.Captcha c = service.generate();

        assertThat(c.challengeId()).isNotBlank();
        assertThat(c.image()).startsWith("data:image/png;base64,");
        assertThat(c.image().length()).isGreaterThan(200); // 确实渲染了一张 PNG
        assertThat(store.map).containsKey("authgw:captcha:" + c.challengeId());
    }

    @Test
    void generate_producesFourCharCodeFromSafeAlphabet() {
        CaptchaService.Captcha c = service.generate();
        String code = store.map.get("authgw:captcha:" + c.challengeId());
        assertThat(code).hasSize(4);
        assertThat(code).matches("[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}"); // 无 0/O/1/I/L
    }

    @Test
    void verify_correctAnswer_caseInsensitive_returnsTrueAndConsumes() {
        CaptchaService.Captcha c = service.generate();
        String code = store.map.get("authgw:captcha:" + c.challengeId());

        assertThat(service.verify(c.challengeId(), code.toLowerCase())).isTrue();
        // 一次性：消费后再校验即失败
        assertThat(store.map).doesNotContainKey("authgw:captcha:" + c.challengeId());
        assertThat(service.verify(c.challengeId(), code)).isFalse();
    }

    @Test
    void verify_correctAnswerWithSurroundingSpaces_trimmedAndPasses() {
        CaptchaService.Captcha c = service.generate();
        String code = store.map.get("authgw:captcha:" + c.challengeId());
        assertThat(service.verify(c.challengeId(), "  " + code + " ")).isTrue();
    }

    @Test
    void verify_wrongAnswer_returnsFalse_andStillConsumesToBlockRepeatGuessing() {
        CaptchaService.Captcha c = service.generate();

        assertThat(service.verify(c.challengeId(), "9999")).isFalse();
        assertThat(store.map).doesNotContainKey("authgw:captcha:" + c.challengeId());
    }

    @Test
    void verify_nullBlankOrUnknownChallenge_returnsFalse() {
        assertThat(service.verify(null, "abcd")).isFalse();
        assertThat(service.verify("cid", null)).isFalse();
        assertThat(service.verify(" ", "abcd")).isFalse();
        assertThat(service.verify("cid", "  ")).isFalse();
        assertThat(service.verify("nonexistent-challenge", "abcd")).isFalse();
    }

    static class InMemoryStore implements SmsCodeStore {
        final Map<String, String> map = new HashMap<>();

        @Override
        public void setValue(String key, String value, Duration ttl) {
            map.put(key, value);
        }

        @Override
        public Optional<String> getValue(String key) {
            return Optional.ofNullable(map.get(key));
        }

        @Override
        public boolean delete(String key) {
            return map.remove(key) != null;
        }

        @Override
        public long increment(String key, Duration ttl) {
            long n = Long.parseLong(map.getOrDefault(key, "0")) + 1;
            map.put(key, String.valueOf(n));
            return n;
        }

        @Override
        public long getCounter(String key) {
            return Long.parseLong(map.getOrDefault(key, "0"));
        }

        @Override
        public Optional<Long> getRemainingTtlSeconds(String key) {
            return Optional.empty();
        }
    }
}
