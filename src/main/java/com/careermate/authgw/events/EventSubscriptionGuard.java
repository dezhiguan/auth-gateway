package com.careermate.authgw.events;

import com.careermate.authgw.auth.AuthProperties;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class EventSubscriptionGuard implements ApplicationListener<ContextRefreshedEvent>, EnvironmentAware {

    private static final Logger log = LoggerFactory.getLogger(EventSubscriptionGuard.class);

    private final JdbcTemplate jdbcTemplate;
    private final AuthProperties authProperties;
    private Environment environment;

    public EventSubscriptionGuard(JdbcTemplate jdbcTemplate, AuthProperties authProperties) {
        this.jdbcTemplate = jdbcTemplate;
        this.authProperties = authProperties;
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        if (authProperties.getEvents().isDevAllowEmptySecret()) {
            if (environment != null && environment.acceptsProfiles(Profiles.of("dev"))) {
                log.warn("auth.events.dev-allow-empty-secret=true, skipping subscription guard");
                return;
            }
            throw new IllegalStateException("auth.events.dev-allow-empty-secret is only allowed in dev profile");
        }

        List<SubscriptionSecret> secrets = jdbcTemplate.query("""
                        SELECT subscriber, hmac_secret
                        FROM event_subscriptions
                        WHERE status = 'ACTIVE'
                        """,
                (rs, rowNum) -> new SubscriptionSecret(
                        rs.getString("subscriber"),
                        rs.getString("hmac_secret")));

        for (SubscriptionSecret secret : secrets) {
            validate(secret);
        }
    }

    private void validate(SubscriptionSecret subscriptionSecret) {
        String hmacSecret = subscriptionSecret.hmacSecret();
        if (hmacSecret == null || hmacSecret.isBlank() || hmacSecret.startsWith("<TBD")) {
            throw new IllegalStateException(
                    "event subscription [" + subscriptionSecret.subscriber() + "] hmac_secret missing");
        }
        if (hmacSecret.length() < 16) {
            throw new IllegalStateException(
                    "event subscription [" + subscriptionSecret.subscriber() + "] hmac_secret too short");
        }
    }

    private record SubscriptionSecret(String subscriber, String hmacSecret) {
    }
}
