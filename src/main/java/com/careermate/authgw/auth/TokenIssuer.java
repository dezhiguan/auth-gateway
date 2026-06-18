package com.careermate.authgw.auth;

import com.careermate.authgw.crypto.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TokenIssuer {

    private final JwtSigner jwtSigner;
    private final JdbcTemplate jdbcTemplate;
    private final AuthProperties properties;

    public TokenIssuer(JwtSigner jwtSigner, JdbcTemplate jdbcTemplate, AuthProperties properties) {
        this.jwtSigner = jwtSigner;
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
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
                sessionId, user.id(), client.clientId(), user.sessionVersion());
        jdbcTemplate.update("""
                        INSERT INTO refresh_tokens(token_hash, family_id, session_id, expires_at)
                        VALUES (?, ?, ?, ?)
                        """,
                sha256Hex(refreshToken), familyId, sessionId, Date.from(refreshExpiresAt));

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

    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }
}
