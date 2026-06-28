package com.careermate.authgw.auth;

import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class TokenStatusService {

    private final JdbcTemplate jdbcTemplate;
    private final AuthProperties properties;

    public TokenStatusService(JdbcTemplate jdbcTemplate, AuthProperties properties) {
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
    }

    public void requireActiveUserAccessToken(JWTClaimsSet claims) {
        if (!isActiveUserAccessToken(claims)) {
            throw new AuthException(401, "ACCESS_TOKEN_INACTIVE", "access token is inactive");
        }
    }

    public boolean isActiveUserAccessToken(JWTClaimsSet claims) {
        if (claims == null
                || !properties.getIssuer().equals(claims.getIssuer())
                || claims.getExpirationTime() == null
                || claims.getExpirationTime().before(new Date())
                || !"user".equals(stringClaim(claims, "principal_type"))) {
            return false;
        }
        Long userId = longClaim(claims, "user_id");
        Long sessionVersion = longClaim(claims, "session_version");
        String sessionId = stringClaim(claims, "session_id");
        if (userId == null || sessionVersion == null || !StringUtils.hasText(sessionId)) {
            return false;
        }
        Integer active = jdbcTemplate.queryForObject("""
                        SELECT COUNT(*)
                        FROM auth_sessions s
                        JOIN auth_users u ON u.id = s.user_id
                        WHERE s.session_id = ?
                          AND s.user_id = ?
                          AND s.session_version = ?
                          AND u.session_version = ?
                          AND s.revoked_at IS NULL
                          AND u.status = 'ACTIVE'
                        """,
                Integer.class,
                sessionId, userId, sessionVersion, sessionVersion);
        return active != null && active == 1;
    }

    public Map<String, Object> userInfo(JWTClaimsSet claims) {
        requireActiveUserAccessToken(claims);
        return Map.ofEntries(
                Map.entry("sub", claims.getSubject()),
                Map.entry("user_id", longClaim(claims, "user_id")),
                Map.entry("principal_type", stringClaim(claims, "principal_type")),
                Map.entry("platform_role", stringClaim(claims, "platform_role")),
                Map.entry("rag_role", stringClaim(claims, "rag_role")),
                Map.entry("scopes", listClaim(claims, "scopes")),
                Map.entry("rag_readable_kb_ids", listClaim(claims, "rag_readable_kb_ids")),
                Map.entry("rag_writable_kb_ids", listClaim(claims, "rag_writable_kb_ids")),
                Map.entry("session_id", stringClaim(claims, "session_id")),
                Map.entry("session_version", longClaim(claims, "session_version")));
    }

    public Map<String, Object> introspection(JWTClaimsSet claims, OAuthClient client) {
        if (!isActiveUserAccessToken(claims) || !audienceAllowed(claims, client)) {
            return Map.of("active", false);
        }
        return Map.ofEntries(
                Map.entry("active", true),
                Map.entry("iss", claims.getIssuer()),
                Map.entry("sub", claims.getSubject()),
                Map.entry("aud", claims.getAudience()),
                Map.entry("exp", claims.getExpirationTime().toInstant().getEpochSecond()),
                Map.entry("iat", claims.getIssueTime() == null ? 0L : claims.getIssueTime().toInstant().getEpochSecond()),
                Map.entry("jti", claims.getJWTID()),
                Map.entry("principal_type", stringClaim(claims, "principal_type")),
                Map.entry("user_id", longClaim(claims, "user_id")),
                Map.entry("platform_role", stringClaim(claims, "platform_role")),
                Map.entry("rag_role", stringClaim(claims, "rag_role")),
                Map.entry("scopes", listClaim(claims, "scopes")),
                Map.entry("session_id", stringClaim(claims, "session_id")),
                Map.entry("session_version", longClaim(claims, "session_version")),
                Map.entry("client_id", client.clientId()));
    }

    private boolean audienceAllowed(JWTClaimsSet claims, OAuthClient client) {
        return claims.getAudience() != null
                && claims.getAudience().stream().anyMatch(client.allowedAudiences()::contains);
    }

    private String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value == null ? "" : String.valueOf(value);
    }

    private Long longClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return value == null ? null : Long.parseLong(String.valueOf(value));
    }

    private List<?> listClaim(JWTClaimsSet claims, String name) {
        try {
            List<?> values = claims.getListClaim(name);
            return values == null ? List.of() : values;
        } catch (Exception ex) {
            return List.of();
        }
    }
}
