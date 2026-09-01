package com.careermate.authgw.config;

import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

/**
 * Redis 密码在部署环境里存在两个 key：Spring 真正绑定的 {@code SPRING_DATA_REDIS_PASSWORD}，
 * 以及共享 env 里历史沿用、其它服务仍在读的 {@code REDIS_PASSWORD}。
 *
 * <p>前者一旦被写成空串，Spring 会安静地以「无密码」建连；而 Redis 开了 requirepass 之后，
 * 已建立的老连接不会被踢，故障要等到某次重启才引爆，届时所有依赖 Redis 的链路一起 NOAUTH。
 * 2026-09-01 登录全站不可用即由此而来。
 *
 * <p>这里做两件事：密码为空时回落到 {@code REDIS_PASSWORD}；prod 下两者都为空则拒绝启动，
 * 让配置漂移在部署阶段暴露，而不是以线上 500 的形式暴露。
 */
public class RedisPasswordEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    static final String PASSWORD_PROPERTY = "spring.data.redis.password";
    static final String HOST_PROPERTY = "spring.data.redis.host";
    static final String FALLBACK_PROPERTY = "REDIS_PASSWORD";
    static final String SOURCE_NAME = "redisPasswordFallback";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (!StringUtils.hasText(environment.getProperty(HOST_PROPERTY))) {
            // 没配 Redis 的环境（本地、单测）不介入
            return;
        }
        if (StringUtils.hasText(environment.getProperty(PASSWORD_PROPERTY))) {
            return;
        }
        String fallback = environment.getProperty(FALLBACK_PROPERTY);
        if (StringUtils.hasText(fallback)) {
            environment.getPropertySources()
                    .addFirst(new MapPropertySource(SOURCE_NAME, Map.of(PASSWORD_PROPERTY, fallback)));
            return;
        }
        if (environment.matchesProfiles("prod")) {
            throw new IllegalStateException(
                    "Redis 密码缺失：" + PASSWORD_PROPERTY + " 与 " + FALLBACK_PROPERTY
                            + " 均为空，拒绝以无密码方式连接生产 Redis。请修正 /opt/shared/env/auth-gateway.env "
                            + "后重建 auth-gateway-env secret 并重新滚动。");
        }
    }

    @Override
    public int getOrder() {
        // 需在 ConfigData 处理完（profile、application-*.yml 已就绪）之后再判断
        return Ordered.LOWEST_PRECEDENCE;
    }
}
