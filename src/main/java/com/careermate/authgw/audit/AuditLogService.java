package com.careermate.authgw.audit;

import com.careermate.authgw.auth.TokenHasher;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AuditLogService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final TokenHasher tokenHasher;

    public AuditLogService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper, TokenHasher tokenHasher) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.tokenHasher = tokenHasher;
    }

    public void info(String eventType, Long actorUserId, String clientId, Map<String, ?> details) {
        write(eventType, actorUserId, clientId, "INFO", details);
    }

    public void high(String eventType, Long actorUserId, String clientId, Map<String, ?> details) {
        write(eventType, actorUserId, clientId, "HIGH", details);
    }

    public void write(String eventType, Long actorUserId, String clientId, String riskLevel, Map<String, ?> details) {
        jdbcTemplate.update("""
                        INSERT INTO audit_logs(event_type, actor_user_id, client_id, risk_level, details)
                        VALUES (?, ?, ?, ?, ?::jsonb)
                        """,
                eventType,
                actorUserId,
                clientId,
                riskLevel,
                toJson(sanitize(details)));
    }

    private Map<String, Object> sanitize(Map<String, ?> details) {
        Map<String, Object> sanitized = new LinkedHashMap<>();
        if (details == null) {
            return sanitized;
        }
        details.forEach((key, value) -> sanitized.put(key, sanitizeValue(key, value)));
        return sanitized;
    }

    private Object sanitizeValue(String key, Object value) {
        if (value == null) {
            return null;
        }
        String lowerKey = key == null ? "" : key.toLowerCase();
        String text = String.valueOf(value);
        if (lowerKey.contains("phone")) {
            return maskPhone(text);
        }
        if (lowerKey.contains("token") || lowerKey.contains("assertion")) {
            return tokenHasher.sha256Hex(text).substring(0, 6);
        }
        return value;
    }

    private String maskPhone(String value) {
        String normalized = value.replaceAll("\\D", "");
        if (normalized.length() < 7) {
            return "***";
        }
        return normalized.substring(0, 3) + "****" + normalized.substring(normalized.length() - 4);
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("failed to serialize audit log details", ex);
        }
    }
}
