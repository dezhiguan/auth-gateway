package com.careermate.authgw.sms;

import java.time.Duration;
import java.util.Optional;

public interface SmsCodeStore {

    void setValue(String key, String value, Duration ttl);

    Optional<String> getValue(String key);

    boolean delete(String key);

    long increment(String key, Duration ttl);

    long getCounter(String key);

    Optional<Long> getRemainingTtlSeconds(String key);
}
