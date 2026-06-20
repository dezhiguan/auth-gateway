package com.careermate.authgw.events;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(EventPublisher.class);
    private static final Set<String> KNOWN_EVENT_TYPES = Set.of(
            "session.revoked",
            "user.password.changed",
            "consent.revoked",
            "refresh.replay_detected");

    private final JdbcTemplate jdbcTemplate;
    private final EventOutboxRepository eventOutboxRepository;
    private final EventDelivery eventDelivery;
    private final Set<String> emptySubscriptionWarnings = ConcurrentHashMap.newKeySet();

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
        Map<String, Object> envelope = Map.ofEntries(
                Map.entry("event_id", eventId),
                Map.entry("type", eventType),
                Map.entry("event_type", eventType),
                Map.entry("occurred_at", occurredAt.getEpochSecond()),
                Map.entry("occurred_at_iso", occurredAt.toString()),
                Map.entry("data", payload),
                Map.entry("payload", payload));
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
        List<Subscription> subscriptions = jdbcTemplate.query("""
                        SELECT subscriber, endpoint_url, hmac_secret
                        FROM event_subscriptions
                        WHERE status = 'ACTIVE' AND jsonb_exists(event_types, ?)
                        """,
                (rs, rowNum) -> new Subscription(
                        rs.getString("subscriber"),
                        rs.getString("endpoint_url"),
                        rs.getString("hmac_secret")),
                eventType);
        if (subscriptions.isEmpty()
                && KNOWN_EVENT_TYPES.contains(eventType)
                && emptySubscriptionWarnings.add(eventType)) {
            log.warn("no active event subscriptions found for known auth event type={}", eventType);
        }
        return subscriptions;
    }

    private record Subscription(String subscriber, String endpointUrl, String hmacSecret) {
    }
}
