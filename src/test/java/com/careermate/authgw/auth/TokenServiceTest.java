package com.careermate.authgw.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.events.EventPublisher;
import com.nimbusds.jwt.JWTClaimsSet;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock JdbcTemplate jdbcTemplate;
    @Mock TokenHasher tokenHasher;
    @Mock TokenIssuer tokenIssuer;
    @Mock AuthUserRepository userRepository;
    @Mock PasswordHasher passwordHasher;
    @Mock EventPublisher eventPublisher;
    @Mock ResultSet resultSet;

    @Test
    @SuppressWarnings("unchecked")
    void refreshDetectsReplayWhenTokenWasAlreadyRotated() throws Exception {
        when(tokenHasher.sha256Hex("refresh-token")).thenReturn("hash");
        when(jdbcTemplate.query(anyString(), any(ResultSetExtractor.class), any())).thenAnswer(invocation -> {
            ResultSetExtractor<?> extractor = invocation.getArgument(1);
            when(resultSet.next()).thenReturn(true);
            refreshRow(Timestamp.from(Instant.now().plusSeconds(60)), Timestamp.from(Instant.now()), null, null, "careermate-api");
            return extractor.extractData(resultSet);
        });

        assertThatThrownBy(() -> tokenService().refresh("refresh-token", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("REFRESH_REPLAY_DETECTED"));
        verify(eventPublisher).publish("refresh.replay_detected", java.util.Map.of("family_id", "family-1"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void refreshRotatesTokenWhenSessionAndUserAreActive() throws Exception {
        AuthUser user = new AuthUser(12, "phone", null, "amy", "pwd", "USER", 4, "ACTIVE");
        TokenPair pair = new TokenPair("access", "refresh2", "Bearer", 900);
        when(tokenHasher.sha256Hex("refresh-token")).thenReturn("hash");
        when(jdbcTemplate.query(anyString(), any(ResultSetExtractor.class), any())).thenAnswer(invocation -> {
            ResultSetExtractor<?> extractor = invocation.getArgument(1);
            when(resultSet.next()).thenReturn(true);
            refreshRow(Timestamp.from(Instant.now().plusSeconds(60)), null, null, null, "careermate-api");
            return extractor.extractData(resultSet);
        });
        when(userRepository.findById(12)).thenReturn(Optional.of(user));
        when(jdbcTemplate.update(org.mockito.ArgumentMatchers.contains("SET rotated_at = now()"),
                org.mockito.ArgumentMatchers.<Object>any())).thenReturn(1);
        when(tokenIssuer.issueRotatedRefresh(user, client(), "careermate-api", "sid-1", "family-1")).thenReturn(pair);

        assertThat(tokenService().refresh("refresh-token", client())).isSameAs(pair);
    }

    @Test
    @SuppressWarnings("unchecked")
    void refreshRejectsExpiredToken() throws Exception {
        when(tokenHasher.sha256Hex("refresh-token")).thenReturn("hash");
        when(jdbcTemplate.query(anyString(), any(ResultSetExtractor.class), any())).thenAnswer(invocation -> {
            ResultSetExtractor<?> extractor = invocation.getArgument(1);
            when(resultSet.next()).thenReturn(true);
            refreshRow(Timestamp.from(Instant.now().minusSeconds(60)), null, null, null, "careermate-api");
            return extractor.extractData(resultSet);
        });

        assertThatThrownBy(() -> tokenService().refresh("refresh-token", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("REFRESH_TOKEN_INVALID"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void refreshRejectsRevokedToken() throws Exception {
        when(tokenHasher.sha256Hex("refresh-token")).thenReturn("hash");
        when(jdbcTemplate.query(anyString(), any(ResultSetExtractor.class), any())).thenAnswer(invocation -> {
            ResultSetExtractor<?> extractor = invocation.getArgument(1);
            when(resultSet.next()).thenReturn(true);
            refreshRow(Timestamp.from(Instant.now().plusSeconds(60)), null, Timestamp.from(Instant.now()), null, "careermate-api");
            return extractor.extractData(resultSet);
        });

        assertThatThrownBy(() -> tokenService().refresh("refresh-token", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("REFRESH_TOKEN_INVALID"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void refreshRejectsRevokedSession() throws Exception {
        AuthUser user = new AuthUser(12, "phone", null, "amy", "pwd", "USER", 4, "ACTIVE");
        when(tokenHasher.sha256Hex("refresh-token")).thenReturn("hash");
        when(jdbcTemplate.query(anyString(), any(ResultSetExtractor.class), any())).thenAnswer(invocation -> {
            ResultSetExtractor<?> extractor = invocation.getArgument(1);
            when(resultSet.next()).thenReturn(true);
            refreshRow(Timestamp.from(Instant.now().plusSeconds(60)), null, null, Timestamp.from(Instant.now()), "careermate-api");
            return extractor.extractData(resultSet);
        });
        when(userRepository.findById(12)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> tokenService().refresh("refresh-token", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("REFRESH_SESSION_REVOKED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void refreshRejectsSessionVersionMismatch() throws Exception {
        AuthUser user = new AuthUser(12, "phone", null, "amy", "pwd", "USER", 9, "ACTIVE");
        when(tokenHasher.sha256Hex("refresh-token")).thenReturn("hash");
        when(jdbcTemplate.query(anyString(), any(ResultSetExtractor.class), any())).thenAnswer(invocation -> {
            ResultSetExtractor<?> extractor = invocation.getArgument(1);
            when(resultSet.next()).thenReturn(true);
            refreshRow(Timestamp.from(Instant.now().plusSeconds(60)), null, null, null, "careermate-api");
            return extractor.extractData(resultSet);
        });
        when(userRepository.findById(12)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> tokenService().refresh("refresh-token", client()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("REFRESH_SESSION_REVOKED"));
    }

    @Test
    void logoutRequiresSessionId() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();

        assertThatThrownBy(() -> tokenService().logout(claims))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SESSION_ID_MISSING"));
    }

    @Test
    void logoutRevokesSessionAndPublishesJti() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("session_id", "sid-1")
                .claim("jti", "jti-1")
                .build();

        tokenService().logout(claims);

        verify(jdbcTemplate).update(org.mockito.ArgumentMatchers.contains("UPDATE auth_sessions"), org.mockito.ArgumentMatchers.eq("sid-1"));
        verify(eventPublisher).publish("session.revoked", java.util.Map.of("session_id", "sid-1", "reason", "logout", "jti", "jti-1"));
    }

    @Test
    void logoutAllRejectsBadPassword() {
        AuthUser user = new AuthUser(12, "phone", null, "amy", "pwd-hash", "USER", 4, "ACTIVE");
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();
        when(userRepository.findById(12)).thenReturn(Optional.of(user));
        when(passwordHasher.matches("wrong", "pwd-hash")).thenReturn(false);

        assertThatThrownBy(() -> tokenService().logoutAll(claims, "wrong"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("BAD_CREDENTIALS"));
    }

    @Test
    void logoutAllIncrementsSessionVersionAndRevokesTokens() {
        AuthUser user = new AuthUser(12, "phone", null, "amy", "pwd-hash", "USER", 4, "ACTIVE");
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();
        when(userRepository.findById(12)).thenReturn(Optional.of(user));
        when(passwordHasher.matches("secret", "pwd-hash")).thenReturn(true);

        tokenService().logoutAll(claims, "secret");

        verify(jdbcTemplate).update("UPDATE auth_users SET session_version = session_version + 1 WHERE id = ?", 12L);
        verify(eventPublisher).publish("session.revoked", java.util.Map.of("user_id", 12L, "reason", "logout-all"));
    }

    private void refreshRow(Timestamp expiresAt, Timestamp rotatedAt, Timestamp revokedAt, Timestamp sessionRevokedAt, String audience) throws Exception {
        when(resultSet.getString("token_hash")).thenReturn("hash");
        when(resultSet.getString("family_id")).thenReturn("family-1");
        when(resultSet.getString("session_id")).thenReturn("sid-1");
        when(resultSet.getTimestamp("expires_at")).thenReturn(expiresAt);
        when(resultSet.getTimestamp("rotated_at")).thenReturn(rotatedAt);
        when(resultSet.getTimestamp("revoked_at")).thenReturn(revokedAt);
        when(resultSet.getLong("user_id")).thenReturn(12L);
        when(resultSet.getLong("session_version")).thenReturn(4L);
        when(resultSet.getTimestamp("session_revoked_at")).thenReturn(sessionRevokedAt);
        when(resultSet.getString("audience")).thenReturn(audience);
    }

    private TokenService tokenService() {
        return new TokenService(jdbcTemplate, tokenHasher, tokenIssuer, userRepository, passwordHasher, eventPublisher);
    }

    private static OAuthClient client() {
        return new OAuthClient("ragforge-admin-backend", "RAGForge", "private_key_jwt", null,
                Set.of("refresh_token"), Set.of("careermate-api"), Set.of("rag:search"), "ACTIVE");
    }
}
