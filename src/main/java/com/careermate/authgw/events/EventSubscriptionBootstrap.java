package com.careermate.authgw.events;

import jakarta.annotation.PostConstruct;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class EventSubscriptionBootstrap {

    private static final Logger log = LoggerFactory.getLogger(EventSubscriptionBootstrap.class);

    private static final String DEFAULT_EVENT_TYPES =
            "[\"session.revoked\",\"user.password.changed\",\"consent.revoked\",\"refresh.replay_detected\"]";

    private final JdbcTemplate jdbcTemplate;
    private final List<ConfiguredSubscription> subscriptions;

    public EventSubscriptionBootstrap(
            JdbcTemplate jdbcTemplate,
            @Value("${auth.events.subscriptions.ragforge.endpoint:}") String ragforgeEndpoint,
            @Value("${auth.events.subscriptions.ragforge.hmac-secret:}") String ragforgeHmacSecret,
            @Value("${auth.events.subscriptions.careermate.endpoint:}") String careermateEndpoint,
            @Value("${auth.events.subscriptions.careermate.hmac-secret:}") String careermateHmacSecret) {
        this.jdbcTemplate = jdbcTemplate;
        this.subscriptions = List.of(
                new ConfiguredSubscription("ragforge", ragforgeEndpoint, ragforgeHmacSecret),
                new ConfiguredSubscription("careermate", careermateEndpoint, careermateHmacSecret));
    }

    @PostConstruct
    public void syncConfiguredSubscriptions() {
        for (ConfiguredSubscription subscription : subscriptions) {
            if (!StringUtils.hasText(subscription.endpoint())) {
                continue;
            }
            upsert(subscription);
        }
    }

    private void upsert(ConfiguredSubscription subscription) {
        int updated = jdbcTemplate.update(
                """
                UPDATE event_subscriptions
                SET endpoint_url = ?,
                    hmac_secret = CASE WHEN ? <> '' THEN ? ELSE hmac_secret END,
                    status = 'ACTIVE'
                WHERE subscriber = ?
                """,
                subscription.endpoint(),
                subscription.hmacSecret(),
                subscription.hmacSecret(),
                subscription.subscriber());
        if (updated == 0) {
            jdbcTemplate.update(
                    """
                    INSERT INTO event_subscriptions(subscriber, event_types, endpoint_url, hmac_key_id, hmac_secret, status)
                    VALUES (?, CAST(? AS jsonb), ?, ?, ?, 'ACTIVE')
                    ON CONFLICT DO NOTHING
                    """,
                    subscription.subscriber(),
                    DEFAULT_EVENT_TYPES,
                    subscription.endpoint(),
                    subscription.subscriber() + "-hmac-key",
                    subscription.hmacSecret());
        }
        if (!StringUtils.hasText(subscription.hmacSecret())) {
            log.warn(
                    "auth event subscription activated without configured secret; subscriber={} endpoint={}",
                    subscription.subscriber(),
                    subscription.endpoint());
        } else {
            log.info(
                    "auth event subscription activated; subscriber={} endpoint={}",
                    subscription.subscriber(),
                    subscription.endpoint());
        }
    }

    private record ConfiguredSubscription(String subscriber, String endpoint, String hmacSecret) {
    }
}
