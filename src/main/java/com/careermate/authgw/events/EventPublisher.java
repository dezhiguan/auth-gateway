package com.careermate.authgw.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(EventPublisher.class);

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public EventPublisher(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public void publish(String eventType, Map<String, Object> payload) {
        Instant occurredAt = Instant.now();
        Map<String, Object> envelope = Map.of(
                "event_type", eventType,
                "occurred_at", occurredAt.toString(),
                "payload", payload);
        List<Subscription> subscriptions = subscriptionsFor(eventType);
        if (subscriptions.isEmpty()) {
            log.info("auth event published type={}, at={}, payload={}, deliveries=0", eventType, occurredAt, payload);
            return;
        }
        subscriptions.forEach(subscription -> log.info(
                "auth event delivery prepared type={}, endpoint={}, hmac_key_id={}, signature={}",
                eventType,
                subscription.endpointUrl(),
                subscription.hmacKeyId(),
                signature(subscription.hmacKeyId(), envelope)));
    }

    private List<Subscription> subscriptionsFor(String eventType) {
        return jdbcTemplate.query("""
                        SELECT endpoint_url, hmac_key_id
                        FROM event_subscriptions
                        WHERE status = 'ACTIVE' AND jsonb_exists(event_types, ?)
                        """,
                (rs, rowNum) -> new Subscription(rs.getString("endpoint_url"), rs.getString("hmac_key_id")),
                eventType);
    }

    private String signature(String hmacKeyId, Map<String, Object> envelope) {
        try {
            byte[] body = objectMapper.writeValueAsBytes(envelope);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKeyId.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(body);
            return "sha256=" + HexFormat.of().formatHex(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("failed to sign auth event", ex);
        }
    }

    private record Subscription(String endpointUrl, String hmacKeyId) {
    }
}
