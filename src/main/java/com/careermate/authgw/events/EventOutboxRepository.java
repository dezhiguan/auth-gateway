package com.careermate.authgw.events;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class EventOutboxRepository {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public EventOutboxRepository(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public void createPending(String eventId, String eventType, String subscriber, String endpointUrl,
            Map<String, Object> envelope) {
        jdbcTemplate.update("""
                        INSERT INTO event_outbox (event_id, event_type, subscriber, endpoint_url, payload)
                        VALUES (?, ?, ?, ?, ?::jsonb)
                        """,
                eventId,
                eventType,
                subscriber,
                endpointUrl,
                toJson(envelope));
    }

    public void markDelivered(String eventId, int attempts, Instant deliveredAt) {
        jdbcTemplate.update("""
                        UPDATE event_outbox
                        SET status = 'DELIVERED', attempts = ?, last_error = NULL, delivered_at = ?
                        WHERE event_id = ?
                        """,
                attempts,
                deliveredAt,
                eventId);
    }

    public void markFailed(String eventId, int attempts, String lastError) {
        jdbcTemplate.update("""
                        UPDATE event_outbox
                        SET status = 'FAILED', attempts = ?, last_error = ?
                        WHERE event_id = ?
                        """,
                attempts,
                lastError,
                eventId);
    }

    private String toJson(Map<String, Object> envelope) {
        try {
            return objectMapper.writeValueAsString(envelope);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("failed to serialize auth event outbox payload", ex);
        }
    }
}
