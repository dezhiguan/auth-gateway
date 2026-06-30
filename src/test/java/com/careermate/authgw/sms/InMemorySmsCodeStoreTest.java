package com.careermate.authgw.sms;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class InMemorySmsCodeStoreTest {

    @Test
    void setGetDeleteValue() {
        InMemorySmsCodeStore store = new InMemorySmsCodeStore();

        store.setValue("key", "value", Duration.ofMinutes(1));

        assertThat(store.getValue("key")).contains("value");
        assertThat(store.delete("key")).isTrue();
        assertThat(store.delete("key")).isFalse();
        assertThat(store.getValue("key")).isEmpty();
    }

    @Test
    void valueExpiresAndIsRemoved() throws Exception {
        InMemorySmsCodeStore store = new InMemorySmsCodeStore();
        store.setValue("key", "value", Duration.ofMillis(5));

        Thread.sleep(20);

        assertThat(store.getValue("key")).isEmpty();
        assertThat(store.getRemainingTtlSeconds("key")).isEmpty();
    }

    @Test
    void incrementStartsAtOneAndKeepsExistingTtl() {
        InMemorySmsCodeStore store = new InMemorySmsCodeStore();

        assertThat(store.increment("counter", Duration.ofSeconds(30))).isEqualTo(1);
        assertThat(store.increment("counter", Duration.ofSeconds(30))).isEqualTo(2);
        assertThat(store.getCounter("counter")).isEqualTo(2);
        assertThat(store.getRemainingTtlSeconds("counter")).isPresent();
    }

    @Test
    void counterExpiredFallsBackToZeroAndRestartsAtOne() throws Exception {
        InMemorySmsCodeStore store = new InMemorySmsCodeStore();
        assertThat(store.increment("counter", Duration.ofMillis(5))).isEqualTo(1);

        Thread.sleep(20);

        assertThat(store.getCounter("counter")).isZero();
        assertThat(store.increment("counter", Duration.ofSeconds(30))).isEqualTo(1);
    }

    @Test
    void cleanupExpiredRunsBeforeIncrementingOtherKeys() throws Exception {
        InMemorySmsCodeStore store = new InMemorySmsCodeStore();
        store.setValue("expired", "value", Duration.ofMillis(5));

        Thread.sleep(20);
        store.increment("counter", Duration.ofSeconds(30));

        assertThat(store.getValue("expired")).isEmpty();
    }
}
