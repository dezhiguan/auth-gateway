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
    private final AuthProperties properties;

    public TokenService(
            JdbcTemplate jdbcTemplate,
            TokenHasher tokenHasher,
            TokenIssuer tokenIssuer,
            AuthUserRepository userRepository,
            PasswordHasher passwordHasher,
            EventPublisher eventPublisher,
            AuthProperties properties) {
        this.jdbcTemplate = jdbcTemplate;
        this.tokenHasher = tokenHasher;
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.eventPublisher = eventPublisher;
        this.properties = properties;
    }

    @Transactional(noRollbackFor = AuthException.class)
    public TokenPair refresh(String refreshToken, OAuthClient client) {
        RefreshRecord refresh = findRefresh(refreshToken);
        if (refresh.revokedAt() != null || refresh.expired()) {
            throw new AuthException(401, "REFRESH_TOKEN_INVALID", "refresh token is invalid");
        }

        AuthUser user = userRepository.findById(refresh.userId())
                .orElseThrow(() -> new AuthException(401, "REFRESH_SESSION_INVALID", "refresh session is invalid"));
        if (refresh.sessionRevoked() || user.sessionVersion() != refresh.sessionVersion()) {
            throw new AuthException(401, "REFRESH_SESSION_REVOKED", "refresh session is revoked");
        }

        // 已旋转的 token 又被提交：可能是并发双刷、也可能是「客户端从未收到旋转响应」
        // （笔记本合盖休眠、响应在途丢失）后带着旧令牌回来，还可能是真正的重放攻击。交给
        // handleRotatedReuse 用「宽限期 + 后继是否已被消费」两个信号区分，避免误灭族。
        if (refresh.rotatedAt() != null) {
            return handleRotatedReuse(refresh, user, client);
        }

        int rotated = jdbcTemplate.update("""
                        UPDATE refresh_tokens
                        SET rotated_at = now()
                        WHERE token_hash = ? AND rotated_at IS NULL AND revoked_at IS NULL
                        """,
                tokenHasher.sha256Hex(refreshToken));
        if (rotated == 0) {
            // 读到时未旋转、更新时已被旋转 = 毫秒级并发竞争。重新读取按重用路径处理（必落宽限期内）。
            return handleRotatedReuse(findRefresh(refreshToken), user, client);
        }

        // 正常旋转：签发后继并回填「前驱→后继」链接。
        return issueAndLink(refresh, user, client);
    }

    /**
     * 已旋转 refresh token 被再次使用的处置：
     * <ul>
     *   <li>宽限期内 → 毫秒级并发双刷/弱网重试，良性补发（保持原行为）；</li>
     *   <li>超出宽限期但后继令牌从未被消费 → 客户端从未收到旋转响应（合盖休眠、响应丢失）的
     *       合法重投递：吊销孤儿后继、从会话补发新令牌，<b>不灭族</b>；</li>
     *   <li>超出宽限期且后继已被消费（链已前进）或缺失 → 真正的重放/分叉 → 灭族。</li>
     * </ul>
     */
    private TokenPair handleRotatedReuse(RefreshRecord refresh, AuthUser user, OAuthClient client) {
        if (withinRotationGrace(refresh.rotatedAt())) {
            eventPublisher.publish("refresh.grace_reuse", Map.of("family_id", refresh.familyId()));
            return issueAndLink(refresh, user, client);
        }
        RefreshRecord successor = findRefreshOrNull(refresh.replacedByHash());
        if (successor != null
                && successor.revokedAt() == null
                && !successor.expired()
                && successor.rotatedAt() == null) {
            // 后继从未被使用 → 客户端没拿到过它 → 合法重投递：吊销孤儿后继，从会话补发新令牌，不灭族。
            eventPublisher.publish("refresh.redelivery", Map.of("family_id", refresh.familyId()));
            revokeToken(successor.tokenHash());
            return issueAndLink(refresh, user, client);
        }
        eventPublisher.publish("refresh.replay_detected", Map.of("family_id", refresh.familyId()));
        revokeFamily(refresh.familyId());
        throw new AuthException(401, "REFRESH_REPLAY_DETECTED", "refresh token replay detected");
    }

    /** 从会话签发一枚新的 refresh token，并把前驱（本次提交的令牌）指向它，形成旋转链。 */
    private TokenPair issueAndLink(RefreshRecord predecessor, AuthUser user, OAuthClient client) {
        TokenPair pair = tokenIssuer.issueRotatedRefresh(
                user, client, predecessor.audience(), predecessor.sessionId(),
                predecessor.familyId(), refreshTtl(predecessor));
        jdbcTemplate.update(
                "UPDATE refresh_tokens SET replaced_by_hash = ? WHERE token_hash = ?",
                tokenHasher.sha256Hex(pair.refreshToken()), predecessor.tokenHash());
        return pair;
    }

    private boolean withinRotationGrace(java.time.Instant rotatedAt) {
        long grace = properties.getRefreshRotationGraceSeconds();
        return grace > 0 && rotatedAt.plusSeconds(grace).isAfter(java.time.Instant.now());
    }

    /** 会话级 refresh TTL（记住我=30天），历史会话无该字段时回退默认值。 */
    private long refreshTtl(RefreshRecord refresh) {
        return refresh.refreshTtlSeconds() != null && refresh.refreshTtlSeconds() > 0
                ? refresh.refreshTtlSeconds()
                : properties.getRefreshTokenTtlSeconds();
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

    private static final String REFRESH_SELECT = """
            SELECT rt.token_hash, rt.family_id, rt.session_id, rt.expires_at,
                   rt.rotated_at, rt.revoked_at, rt.replaced_by_hash,
                   s.user_id, s.session_version, s.revoked_at AS session_revoked_at,
                   s.target_audience AS audience, s.refresh_ttl_seconds
            FROM refresh_tokens rt
            JOIN auth_sessions s ON s.session_id = rt.session_id
            WHERE rt.token_hash = ?
            """;

    private RefreshRecord findRefresh(String refreshToken) {
        return jdbcTemplate.query(REFRESH_SELECT,
                rs -> {
                    if (!rs.next()) {
                        throw new AuthException(401, "REFRESH_TOKEN_INVALID", "refresh token is invalid");
                    }
                    return mapRefresh(rs);
                },
                tokenHasher.sha256Hex(refreshToken));
    }

    /** 按 token 哈希查后继令牌记录；不存在返回 null（重投递判定用，哈希为空直接返回 null）。 */
    private RefreshRecord findRefreshOrNull(String tokenHash) {
        if (tokenHash == null) {
            return null;
        }
        return jdbcTemplate.query(REFRESH_SELECT,
                rs -> rs.next() ? mapRefresh(rs) : null,
                tokenHash);
    }

    private RefreshRecord mapRefresh(ResultSet rs) throws SQLException {
        String audience = rs.getString("audience");
        if (audience == null) {
            throw new AuthException(401, "REFRESH_AUDIENCE_MISSING", "refresh session audience is missing");
        }
        long ttl = rs.getLong("refresh_ttl_seconds");
        Long refreshTtlSeconds = rs.wasNull() ? null : ttl;
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
                rs.getString("audience"),
                refreshTtlSeconds,
                rs.getString("replaced_by_hash"));
    }

    private void revokeToken(String tokenHash) {
        jdbcTemplate.update(
                "UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE token_hash = ?",
                tokenHash);
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
            String audience,
            Long refreshTtlSeconds,
            String replacedByHash) {
        boolean expired() {
            return expiresAt.isBefore(java.time.Instant.now());
        }
    }
}
