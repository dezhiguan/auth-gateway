package com.careermate.authgw.sms;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@ConditionalOnProperty(prefix = "auth.sms", name = "storage", havingValue = "redis")
public class RedisSmsCodeStore implements SmsCodeStore {

    private static final Logger log = LoggerFactory.getLogger(RedisSmsCodeStore.class);

    private final StringRedisTemplate redisTemplate;

    public RedisSmsCodeStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void setValue(String key, String value, Duration ttl) {
        withRetry("set", () -> {
            redisTemplate.opsForValue().set(key, value, ttl);
            return null;
        });
    }

    @Override
    public Optional<String> getValue(String key) {
        return Optional.ofNullable(withRetry("get", () -> redisTemplate.opsForValue().get(key)));
    }

    @Override
    public boolean delete(String key) {
        return Boolean.TRUE.equals(withRetry("delete", () -> redisTemplate.delete(key)));
    }

    @Override
    public long increment(String key, Duration ttl) {
        Long value = withRetry("increment", () -> redisTemplate.opsForValue().increment(key));
        if (value != null && value == 1L) {
            withRetry("expire", () -> redisTemplate.expire(key, ttl));
        }
        return value == null ? 0L : value;
    }

    @Override
    public long getCounter(String key) {
        String value = withRetry("get", () -> redisTemplate.opsForValue().get(key));
        if (!StringUtils.hasText(value)) {
            return 0L;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    @Override
    public Optional<Long> getRemainingTtlSeconds(String key) {
        Long ttl = withRetry("ttl", () -> redisTemplate.getExpire(key, TimeUnit.SECONDS));
        if (ttl == null || ttl < 0) {
            return Optional.empty();
        }
        return Optional.of(ttl);
    }

    /**
     * 连接失效时重试一次。
     *
     * <p>这个 store 在 prod 是登录链路的一部分（RiskService 的失败计数、CaptchaService 的验证码
     * 都经由它），而 Lettuce 默认是一条不带保活的长连接：空闲若干小时后被中间设备静默回收，
     * 下一条命令必然抛 {@code RedisSystemException: java.net.SocketException: Connection reset}，
     * 网关随即 500，调用方（careermate / rag-forge）原样透传成 500 —— 表现为「隔一段时间没人登录，
     * 头一两次登录必失败，之后一路正常」。2026-09-01 09:20 生产实测复现并在网关日志中确认。
     *
     * <p>Lettuce 在这次失败之后会自动重连，所以立即重试一次即可恢复，无需退避。
     * 注意 {@code increment} 不是幂等的：若重置发生在 Redis 已执行 INCR 之后，重试会多计一次，
     * 代价是失败计数早一次触发图形验证码 —— 相比登录直接 500，这个代价是可接受的。
     */
    private <T> T withRetry(String op, Supplier<T> action) {
        try {
            return action.get();
        } catch (RuntimeException ex) {
            if (!isConnectionFailure(ex)) {
                throw ex;
            }
            log.warn("Redis {} 因连接失效重试一次: {}", op, ex.toString());
            return action.get();
        }
    }

    private static boolean isConnectionFailure(Throwable ex) {
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof RedisConnectionFailureException || cause instanceof IOException) {
                return true;
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return false;
    }
}
