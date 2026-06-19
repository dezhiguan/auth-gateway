package com.careermate.authgw.auth;

import com.careermate.authgw.crypto.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TokenIssuer {

    private final JwtSigner jwtSigner;
    private final JdbcTemplate jdbcTemplate;
    private final AuthProperties properties;
    private final TokenHasher tokenHasher;

    public TokenIssuer(JwtSigner jwtSigner, JdbcTemplate jdbcTemplate, AuthProperties properties, TokenHasher tokenHasher) {
        this.jwtSigner = jwtSigner;
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
        this.tokenHasher = tokenHasher;
    }

    public TokenPair issueUserTokens(AuthUser user, OAuthClient client, String targetAud) {
        if (!client.allowedAudiences().contains(targetAud)) {
            throw new AuthException(403, "AUDIENCE_NOT_ALLOWED", "client is not allowed to request target_aud");
        }

        String sessionId = "sid_" + UUID.randomUUID();
        String familyId = "rtf_" + UUID.randomUUID();
        Instant now = Instant.now();
        Instant accessExpiresAt = now.plusSeconds(properties.getAccessTokenTtlSeconds());
        Instant refreshExpiresAt = now.plusSeconds(properties.getRefreshTokenTtlSeconds());
        String jti = "jti_" + UUID.randomUUID();
        String refreshToken = "rt_" + UUID.randomUUID() + "." + UUID.randomUUID();

        jdbcTemplate.update("""
                        INSERT INTO auth_sessions(session_id, user_id, device_id, session_version, created_at)
                        VALUES (?, ?, ?, ?, now())
                        """,
                sessionId, user.id(), targetAud, user.sessionVersion());
        storeRefreshToken(refreshToken, familyId, sessionId, refreshExpiresAt);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .audience(targetAud)
                .subject("user:" + user.id())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(accessExpiresAt))
                .jwtID(jti)
                .claim("principal_type", "user")
                .claim("user_id", user.id())
                .claim("tenant_id", "tn_01J_PERSONAL")
                .claim("platform_role", user.platformRole())
                .claim("rag_role", deriveRagRole(user))
                .claim("rag_readable_kb_ids", List.of())
                .claim("rag_writable_kb_ids", List.of())
                .claim("scopes", scopesFor(user, targetAud))
                .claim("session_id", sessionId)
                .claim("session_version", user.sessionVersion())
                .build();

        return new TokenPair(jwtSigner.sign(claims), refreshToken, "Bearer", properties.getAccessTokenTtlSeconds());
    }

    public TokenPair issueRotatedRefresh(AuthUser user, OAuthClient client, String targetAud, String sessionId, String familyId) {
        if (!client.allowedAudiences().contains(targetAud)) {
            throw new AuthException(403, "AUDIENCE_NOT_ALLOWED", "client is not allowed to request target_aud");
        }

        Instant now = Instant.now();
        Instant accessExpiresAt = now.plusSeconds(properties.getAccessTokenTtlSeconds());
        Instant refreshExpiresAt = now.plusSeconds(properties.getRefreshTokenTtlSeconds());
        String jti = "jti_" + UUID.randomUUID();
        String refreshToken = "rt_" + UUID.randomUUID() + "." + UUID.randomUUID();
        storeRefreshToken(refreshToken, familyId, sessionId, refreshExpiresAt);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .audience(targetAud)
                .subject("user:" + user.id())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(accessExpiresAt))
                .jwtID(jti)
                .claim("principal_type", "user")
                .claim("user_id", user.id())
                .claim("tenant_id", "tn_01J_PERSONAL")
                .claim("platform_role", user.platformRole())
                .claim("rag_role", deriveRagRole(user))
                .claim("rag_readable_kb_ids", List.of())
                .claim("rag_writable_kb_ids", List.of())
                .claim("scopes", scopesFor(user, targetAud))
                .claim("session_id", sessionId)
                .claim("session_version", user.sessionVersion())
                .build();

        return new TokenPair(jwtSigner.sign(claims), refreshToken, "Bearer", properties.getAccessTokenTtlSeconds());
    }

    public String issueExchangedToken(JWTClaimsSet subjectClaims, OAuthClient client, String requestedAudience, Set<String> requestedScopes) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(properties.getExchangeTokenTtlSeconds());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .audience(requestedAudience)
                .subject(subjectClaims.getSubject())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID("jti_" + UUID.randomUUID())
                .claim("principal_type", subjectClaims.getClaim("principal_type"))
                .claim("user_id", subjectClaims.getClaim("user_id"))
                .claim("tenant_id", subjectClaims.getClaim("tenant_id"))
                .claim("platform_role", subjectClaims.getClaim("platform_role"))
                .claim("rag_role", subjectClaims.getClaim("rag_role"))
                .claim("rag_readable_kb_ids", subjectClaims.getClaim("rag_readable_kb_ids"))
                .claim("rag_writable_kb_ids", subjectClaims.getClaim("rag_writable_kb_ids"))
                .claim("scopes", List.copyOf(requestedScopes))
                .claim("session_id", subjectClaims.getClaim("session_id"))
                .claim("session_version", subjectClaims.getClaim("session_version"))
                .claim("azp", client.clientId())
                .claim("act", client.clientId())
                .build();
        return jwtSigner.sign(claims);
    }

    public String issueDelegationToken(
            long delegatedUserId,
            String consentId,
            OAuthClient client,
            String requestedAudience,
            Set<String> scopes,
            List<Long> allowedKbIds,
            long sessionVersion) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(properties.getExchangeTokenTtlSeconds());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .audience(requestedAudience)
                .subject("agent:" + client.clientId() + ":user:" + delegatedUserId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID("jti_" + UUID.randomUUID())
                .claim("principal_type", "agent")
                .claim("client_id", client.clientId())
                .claim("delegated_user_id", delegatedUserId)
                .claim("consent_id", consentId)
                .claim("tenant_id", "tn_01J_PERSONAL")
                .claim("allowed_kb_ids", allowedKbIds)
                .claim("scopes", List.copyOf(scopes))
                .claim("session_version", sessionVersion)
                .build();
        return jwtSigner.sign(claims);
    }

    private void storeRefreshToken(String refreshToken, String familyId, String sessionId, Instant refreshExpiresAt) {
        jdbcTemplate.update("""
                        INSERT INTO refresh_tokens(token_hash, family_id, session_id, expires_at)
                        VALUES (?, ?, ?, ?)
                        """,
                tokenHasher.sha256Hex(refreshToken), familyId, sessionId, Date.from(refreshExpiresAt));
    }

    private String deriveRagRole(AuthUser user) {
        if ("ADMIN".equalsIgnoreCase(user.platformRole())) {
            return "ADMIN";
        }
        return "KB_VIEWER";
    }

    private List<String> scopesFor(AuthUser user, String targetAud) {
        if ("ragforge-admin-api".equals(targetAud) && "ADMIN".equalsIgnoreCase(user.platformRole())) {
            return List.of("rag:admin:read", "rag:admin:write");
        }
        if ("ragforge-admin-api".equals(targetAud)) {
            return List.of("rag:admin:read");
        }
        return List.of();
    }

}
