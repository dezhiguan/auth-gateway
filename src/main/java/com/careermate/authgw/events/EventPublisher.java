package com.careermate.authgw.events;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(EventPublisher.class);

    private final JdbcTemplate jdbcTemplate;
    private final EventOutboxRepository eventOutboxRepository;
    private final EventDelivery eventDelivery;

    public EventPublisher(
            JdbcTemplate jdbcTemplate,
            EventOutboxRepository eventOutboxRepository,
            EventDelivery eventDelivery) {
        this.jdbcTemplate = jdbcTemplate;
        this.eventOutboxRepository = eventOutboxRepository;
        this.eventDelivery = eventDelivery;
    }

    public void publish(String eventType, Map<String, Object> payload) {
        Instant occurredAt = Instant.now();
        List<Subscription> subscriptions = subscriptionsFor(eventType);
        if (subscriptions.isEmpty()) {
            log.info("auth event published type={}, at={}, payload={}, deliveries=0", eventType, occurredAt, payload);
            return;
        }
        subscriptions.forEach(subscription -> publishToSubscription(eventType, occurredAt, payload, subscription));
    }

    private void publishToSubscription(
            String eventType,
            Instant occurredAt,
            Map<String, Object> payload,
            Subscription subscription) {
        String eventId = UUID.randomUUID().toString();
        Map<String, Object> envelope = Map.of(
                "event_id", eventId,
                "event_type", eventType,
                "occurred_at", occurredAt.toString(),
                "payload", payload);
        eventOutboxRepository.createPending(
                eventId,
                eventType,
                subscription.subscriber(),
                subscription.endpointUrl(),
                envelope);
        EventDelivery.DeliveryResult result = eventDelivery.deliver(
                subscription.endpointUrl(),
                subscription.hmacSecret(),
                envelope);
        if (result.delivered()) {
            eventOutboxRepository.markDelivered(eventId, result.attempts(), Instant.now());
            log.info(
                    "auth event delivered event_id={}, type={}, subscriber={}, endpoint={}, attempts={}",
                    eventId,
                    eventType,
                    subscription.subscriber(),
                    subscription.endpointUrl(),
                    result.attempts());
            return;
        }
        eventOutboxRepository.markFailed(eventId, result.attempts(), result.lastError());
        log.error(
                "auth event delivery failed event_id={}, type={}, subscriber={}, endpoint={}, attempts={}, error={}",
                eventId,
                eventType,
                subscription.subscriber(),
                subscription.endpointUrl(),
                result.attempts(),
                result.lastError());
    }

    private List<Subscription> subscriptionsFor(String eventType) {
        return jdbcTemplate.query("""
                        SELECT subscriber, endpoint_url, hmac_secret
                        FROM event_subscriptions
                        WHERE status = 'ACTIVE' AND jsonb_exists(event_types, ?)
                        """,
                (rs, rowNum) -> new Subscription(
                        rs.getString("subscriber"),
                        rs.getString("endpoint_url"),
                        rs.getString("hmac_secret")),
                eventType);
    }

    private record Subscription(String subscriber, String endpointUrl, String hmacSecret) {
    }
}
