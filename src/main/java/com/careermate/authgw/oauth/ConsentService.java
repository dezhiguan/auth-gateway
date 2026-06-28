package com.careermate.authgw.oauth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUser;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.OAuthClientRepository;
import com.careermate.authgw.auth.TokenIssuer;
import com.careermate.authgw.events.EventPublisher;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class ConsentService {

    private static final TypeReference<Set<String>> STRING_SET = new TypeReference<>() {
    };
    private static final TypeReference<List<Long>> LONG_LIST = new TypeReference<>() {
    };
    private static final long DEFAULT_EXPIRES_IN_SECONDS = 30L * 24 * 60 * 60;

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final OAuthClientRepository clientRepository;
    private final AuthUserRepository userRepository;
    private final TokenIssuer tokenIssuer;
    private final EventPublisher eventPublisher;
    private final AuditLogService auditLogService;

    public ConsentService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OAuthClientRepository clientRepository,
            AuthUserRepository userRepository,
            TokenIssuer tokenIssuer,
            EventPublisher eventPublisher,
            AuditLogService auditLogService) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.clientRepository = clientRepository;
        this.userRepository = userRepository;
        this.tokenIssuer = tokenIssuer;
        this.eventPublisher = eventPublisher;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public ConsentRecord create(JWTClaimsSet userClaims, String clientPrincipalId, Set<String> scopes, List<Long> allowedKbIds, Long expiresInSeconds) {
        long userId = requiredUserId(userClaims);
        OAuthClient client = clientRepository.findById(clientPrincipalId)
                .orElseThrow(() -> new AuthException(404, "CLIENT_NOT_FOUND", "client not found"));
        if (scopes == null || scopes.isEmpty() || !client.allowedScopes().containsAll(scopes)) {
            throw new AuthException(403, "SCOPE_NOT_ALLOWED", "consent scopes are not allowed");
        }
        String consentId = "consent_" + UUID.randomUUID();
        Instant expiresAt = Instant.now().plusSeconds(expiresInSeconds == null ? DEFAULT_EXPIRES_IN_SECONDS : expiresInSeconds);
        jdbcTemplate.update("""
                        INSERT INTO agent_consents(consent_id, user_id, client_principal_id, scopes, allowed_kb_ids, expires_at)
                        VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?)
                        """,
                consentId,
                userId,
                clientPrincipalId,
                toJson(scopes),
                toJson(allowedKbIds == null ? List.of() : allowedKbIds),
                Date.from(expiresAt));
        return findById(consentId).orElseThrow();
    }

    public List<ConsentRecord> list(JWTClaimsSet userClaims) {
        long userId = requiredUserId(userClaims);
        return jdbcTemplate.query("""
                        SELECT consent_id, user_id, client_principal_id, scopes::text, allowed_kb_ids::text, expires_at, revoked_at
                        FROM agent_consents
                        WHERE user_id = ?
                        ORDER BY expires_at DESC
                        """,
                (rs, rowNum) -> mapConsent(rs),
                userId);
    }

    @Transactional
    public void revoke(JWTClaimsSet userClaims, String consentId) {
        long userId = requiredUserId(userClaims);
        int updated = jdbcTemplate.update("""
                        UPDATE agent_consents
                        SET revoked_at = COALESCE(revoked_at, now())
                        WHERE consent_id = ? AND user_id = ?
                        """,
                consentId, userId);
        if (updated == 0) {
            throw new AuthException(404, "CONSENT_NOT_FOUND", "consent not found");
        }
        eventPublisher.publish("consent.revoked", Map.of("consent_id", consentId, "user_id", userId));
        auditLogService.high("consent.revoke", userId, null, Map.of("consent_id", consentId));
    }

    @Transactional(readOnly = true)
    public DelegationToken issueDelegationToken(OAuthClient client, String consentId, String requestedAudience, Set<String> requestedScopes) {
        ConsentRecord consent = findById(consentId)
                .orElseThrow(() -> new AuthException(401, "CONSENT_INVALID", "consent is invalid"));
        if (!consent.active()) {
            throw new AuthException(401, "CONSENT_REVOKED", "consent is revoked or expired");
        }
        if (!client.clientId().equals(consent.clientPrincipalId())) {
            throw new AuthException(403, "CONSENT_CLIENT_MISMATCH", "consent does not belong to client");
        }
        if (!client.allowedAudiences().contains(requestedAudience)) {
            throw new AuthException(403, "AUDIENCE_NOT_ALLOWED", "client is not allowed to request audience");
        }
        if (requestedScopes == null || requestedScopes.isEmpty()
                || !client.allowedScopes().containsAll(requestedScopes)
                || !consent.scopes().containsAll(requestedScopes)) {
            throw new AuthException(403, "SCOPE_NOT_ALLOWED", "requested scopes are not allowed");
        }
        AuthUser user = userRepository.findById(consent.userId())
                .orElseThrow(() -> new AuthException(401, "USER_NOT_FOUND", "user not found"));
        String token = tokenIssuer.issueDelegationToken(
                consent.userId(),
                consent.consentId(),
                client,
                requestedAudience,
                requestedScopes,
                consent.allowedKbIds(),
                user.sessionVersion());
        return new DelegationToken(token, "Bearer", "urn:ietf:params:oauth:token-type:access_token", 600L, String.join(" ", requestedScopes));
    }

    public Set<String> parseScopes(String scopes) {
        Set<String> parsed = new LinkedHashSet<>();
        if (!StringUtils.hasText(scopes)) {
            return parsed;
        }
        for (String scope : scopes.trim().split("\\s+")) {
            if (StringUtils.hasText(scope)) {
                parsed.add(scope);
            }
        }
        return parsed;
    }

    private Optional<ConsentRecord> findById(String consentId) {
        List<ConsentRecord> rows = jdbcTemplate.query("""
                        SELECT consent_id, user_id, client_principal_id, scopes::text, allowed_kb_ids::text, expires_at, revoked_at
                        FROM agent_consents
                        WHERE consent_id = ?
                        """,
                (rs, rowNum) -> mapConsent(rs),
                consentId);
        return rows.stream().findFirst();
    }

    private ConsentRecord mapConsent(ResultSet rs) throws SQLException {
        try {
            return new ConsentRecord(
                    rs.getString("consent_id"),
                    rs.getLong("user_id"),
                    rs.getString("client_principal_id"),
                    objectMapper.readValue(rs.getString("scopes"), STRING_SET),
                    objectMapper.readValue(rs.getString("allowed_kb_ids"), LONG_LIST),
                    rs.getTimestamp("expires_at").toInstant(),
                    rs.getTimestamp("revoked_at") == null ? null : rs.getTimestamp("revoked_at").toInstant());
        } catch (Exception ex) {
            throw new SQLException("failed to parse consent JSON", ex);
        }
    }

    private long requiredUserId(JWTClaimsSet claims) {
        Object value = claims.getClaim("user_id");
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("failed to serialize consent JSON", ex);
        }
    }

    public record ConsentRecord(
            String consentId,
            long userId,
            String clientPrincipalId,
            Set<String> scopes,
            List<Long> allowedKbIds,
            Instant expiresAt,
            Instant revokedAt) {
        public boolean active() {
            return revokedAt == null && expiresAt.isAfter(Instant.now());
        }
    }

    public record DelegationToken(
            String accessToken,
            String tokenType,
            String issuedTokenType,
            long expiresIn,
            String scope) {
    }
}
