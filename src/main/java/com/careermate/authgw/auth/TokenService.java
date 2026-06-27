package com.careermate.authgw.auth;

import com.careermate.authgw.events.EventPublisher;
import com.nimbusds.jwt.JWTClaimsSet;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenService {

    private final JdbcTemplate jdbcTemplate;
    private final TokenHasher tokenHasher;
    private final TokenIssuer tokenIssuer;
    private final AuthUserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final EventPublisher eventPublisher;

    public TokenService(
            JdbcTemplate jdbcTemplate,
            TokenHasher tokenHasher,
            TokenIssuer tokenIssuer,
            AuthUserRepository userRepository,
            PasswordHasher passwordHasher,
            EventPublisher eventPublisher) {
        this.jdbcTemplate = jdbcTemplate;
        this.tokenHasher = tokenHasher;
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.eventPublisher = eventPublisher;
    }

    @Transactional(noRollbackFor = AuthException.class)
    public TokenPair refresh(String refreshToken, OAuthClient client) {
        RefreshRecord refresh = findRefresh(refreshToken);
        if (refresh.rotatedAt() != null) {
            eventPublisher.publish("refresh.replay_detected", Map.of("family_id", refresh.familyId()));
            revokeFamily(refresh.familyId());
            throw new AuthException(401, "REFRESH_REPLAY_DETECTED", "refresh token replay detected");
        }
        if (refresh.revokedAt() != null || refresh.expired()) {
            throw new AuthException(401, "REFRESH_TOKEN_INVALID", "refresh token is invalid");
        }

        AuthUser user = userRepository.findById(refresh.userId())
                .orElseThrow(() -> new AuthException(401, "REFRESH_SESSION_INVALID", "refresh session is invalid"));
        if (refresh.sessionRevoked() || user.sessionVersion() != refresh.sessionVersion()) {
            throw new AuthException(401, "REFRESH_SESSION_REVOKED", "refresh session is revoked");
        }

        int rotated = jdbcTemplate.update("""
                        UPDATE refresh_tokens
                        SET rotated_at = now()
                        WHERE token_hash = ? AND rotated_at IS NULL AND revoked_at IS NULL
                        """,
                tokenHasher.sha256Hex(refreshToken));
        if (rotated == 0) {
            eventPublisher.publish("refresh.replay_detected", Map.of("family_id", refresh.familyId()));
            revokeFamily(refresh.familyId());
            throw new AuthException(401, "REFRESH_REPLAY_DETECTED", "refresh token replay detected");
        }

        return tokenIssuer.issueRotatedRefresh(user, client, refresh.audience(), refresh.sessionId(), refresh.familyId());
    }

    @Transactional
    public void logout(JWTClaimsSet claims) {
        String sessionId = stringClaim(claims, "session_id");
        if (sessionId == null) {
            throw new AuthException(401, "SESSION_ID_MISSING", "session_id is missing");
        }
        revokeSession(sessionId);
        // 携带本次 access token 的 jti，订阅方（如 RAGForge）据此把该访问令牌加入吊销名单，
        // 实现"登出后访问令牌立即失效"（单会话登出，按 jti 粒度，不影响其它会话）。
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("session_id", sessionId);
        payload.put("reason", "logout");
        String jti = stringClaim(claims, "jti");
        if (jti == null) {
            jti = claims.getJWTID();
        }
        if (jti != null) {
            payload.put("jti", jti);
        }
        eventPublisher.publish("session.revoked", payload);
    }

    @Transactional
    public void logoutAll(JWTClaimsSet claims, String password) {
        Long userId = longClaim(claims, "user_id");
        if (userId == null) {
            throw new AuthException(401, "USER_ID_MISSING", "user_id is missing");
        }
        AuthUser user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(401, "USER_NOT_FOUND", "user not found"));
        if (!passwordHasher.matches(password, user.passwordHash())) {
            throw new AuthException(401, "BAD_CREDENTIALS", "bad credentials");
        }
        jdbcTemplate.update("UPDATE auth_users SET session_version = session_version + 1 WHERE id = ?", userId);
        jdbcTemplate.update("""
                        UPDATE auth_sessions
                        SET revoked_at = COALESCE(revoked_at, now())
                        WHERE user_id = ? AND revoked_at IS NULL
                        """,
                userId);
        jdbcTemplate.update("""
                        UPDATE refresh_tokens
                        SET revoked_at = COALESCE(revoked_at, now())
                        WHERE session_id IN (SELECT session_id FROM auth_sessions WHERE user_id = ?)
                        """,
                userId);
        eventPublisher.publish("session.revoked", Map.of("user_id", userId, "reason", "logout-all"));
    }

    private RefreshRecord findRefresh(String refreshToken) {
        return jdbcTemplate.query("""
                        SELECT rt.token_hash, rt.family_id, rt.session_id, rt.expires_at,
                               rt.rotated_at, rt.revoked_at,
                               s.user_id, s.session_version, s.revoked_at AS session_revoked_at,
                               s.target_audience AS audience
                        FROM refresh_tokens rt
                        JOIN auth_sessions s ON s.session_id = rt.session_id
                        WHERE rt.token_hash = ?
                        """,
                rs -> {
                    if (!rs.next()) {
                        throw new AuthException(401, "REFRESH_TOKEN_INVALID", "refresh token is invalid");
                    }
                    return mapRefresh(rs);
                },
                tokenHasher.sha256Hex(refreshToken));
    }

    private RefreshRecord mapRefresh(ResultSet rs) throws SQLException {
        String audience = rs.getString("audience");
        if (audience == null) {
            throw new AuthException(401, "REFRESH_AUDIENCE_MISSING", "refresh session audience is missing");
        }
        return new RefreshRecord(
                rs.getString("token_hash"),
                rs.getString("family_id"),
                rs.getString("session_id"),
                rs.getTimestamp("expires_at").toInstant(),
                rs.getTimestamp("rotated_at") == null ? null : rs.getTimestamp("rotated_at").toInstant(),
                rs.getTimestamp("revoked_at") == null ? null : rs.getTimestamp("revoked_at").toInstant(),
                rs.getLong("user_id"),
                rs.getLong("session_version"),
                rs.getTimestamp("session_revoked_at") != null,
                rs.getString("audience"));
    }

    private void revokeFamily(String familyId) {
        jdbcTemplate.update("""
                        UPDATE refresh_tokens
                        SET revoked_at = COALESCE(revoked_at, now())
                        WHERE family_id = ?
                        """,
                familyId);
    }

    private void revokeSession(String sessionId) {
        jdbcTemplate.update("UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE session_id = ?", sessionId);
        jdbcTemplate.update("""
                        UPDATE refresh_tokens
                        SET revoked_at = COALESCE(revoked_at, now())
                        WHERE session_id = ?
                        """,
                sessionId);
    }

    private String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value == null ? null : String.valueOf(value);
    }

    private Long longClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return value == null ? null : Long.parseLong(String.valueOf(value));
    }

    private record RefreshRecord(
            String tokenHash,
            String familyId,
            String sessionId,
            java.time.Instant expiresAt,
            java.time.Instant rotatedAt,
            java.time.Instant revokedAt,
            long userId,
            long sessionVersion,
            boolean sessionRevoked,
            String audience) {
        boolean expired() {
            return expiresAt.isBefore(java.time.Instant.now());
        }
    }
}
