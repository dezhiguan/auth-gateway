package com.careermate.authgw.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.careermate.authgw.crypto.JwksProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class AccessTokenSecurityTest {

    @Mock JwksProvider jwksProvider;
    @Mock JdbcTemplate jdbcTemplate;

    private final AuthProperties properties = new AuthProperties();

    @Test
    void verifierRejectsMissingBearerHeader() {
        assertThatThrownBy(() -> verifier().verify("Basic abc"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("ACCESS_TOKEN_REQUIRED"));
    }

    @Test
    void verifierRejectsInvalidSignature() throws Exception {
        RSAKey trusted = new RSAKeyGenerator(2048).keyID("trusted").generate();
        RSAKey attacker = new RSAKeyGenerator(2048).keyID("attacker").generate();
        when(jwksProvider.publicJwkSet()).thenReturn(new JWKSet(trusted.toPublicJWK()));

        assertThatThrownBy(() -> verifier().verifyToken(sign(activeClaims(), attacker)))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("ACCESS_TOKEN_INVALID"));
    }

    @Test
    void verifierAcceptsTokenSignedByTrustedKey() throws Exception {
        RSAKey trusted = new RSAKeyGenerator(2048).keyID("trusted").generate();
        when(jwksProvider.publicJwkSet()).thenReturn(new JWKSet(trusted.toPublicJWK()));

        JWTClaimsSet claims = verifier().verify("Bearer " + sign(activeClaims(), trusted));

        assertThat(claims.getSubject()).isEqualTo("user:12");
    }

    @Test
    void statusRejectsIssuerMismatchAndExpiredTokenBeforeDatabaseLookup() {
        assertThat(statusService().isActiveUserAccessToken(claims("https://evil.example", Instant.now().plusSeconds(60), "sid-1", 4, "jti-1")))
                .isFalse();
        assertThat(statusService().isActiveUserAccessToken(claims(properties.getIssuer(), Instant.now().minusSeconds(60), "sid-1", 4, "jti-1")))
                .isFalse();
    }

    @Test
    void statusRejectsMissingSessionId() {
        assertThat(statusService().isActiveUserAccessToken(claims(properties.getIssuer(), Instant.now().plusSeconds(60), "", 4, "jti-1")))
                .isFalse();
    }

    @Test
    void statusRejectsSessionVersionMismatch() {
        when(jdbcTemplate.queryForObject(org.mockito.ArgumentMatchers.contains("FROM auth_sessions"), eq(Integer.class),
                eq("sid-1"), eq(12L), eq(4L), eq(4L))).thenReturn(0);

        assertThatThrownBy(() -> statusService().requireActiveUserAccessToken(
                claims(properties.getIssuer(), Instant.now().plusSeconds(60), "sid-1", 4, "jti-1")))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("ACCESS_TOKEN_INACTIVE"));
    }

    @Test
    void statusRejectsRevokedJti() {
        when(jdbcTemplate.queryForObject(org.mockito.ArgumentMatchers.contains("FROM auth_sessions"), eq(Integer.class),
                eq("sid-1"), eq(12L), eq(4L), eq(4L))).thenReturn(1);
        when(jdbcTemplate.queryForObject(org.mockito.ArgumentMatchers.contains("FROM jti_blacklist"), eq(Integer.class),
                eq("jti-1"))).thenReturn(1);

        assertThat(statusService().isActiveUserAccessToken(
                claims(properties.getIssuer(), Instant.now().plusSeconds(60), "sid-1", 4, "jti-1"))).isFalse();
    }

    @Test
    void introspectionReturnsInactiveWhenAudienceIsNotAllowed() {
        JWTClaimsSet claims = claims(properties.getIssuer(), Instant.now().plusSeconds(60), "sid-1", 4, "jti-1");
        when(jdbcTemplate.queryForObject(org.mockito.ArgumentMatchers.contains("FROM auth_sessions"), eq(Integer.class),
                eq("sid-1"), eq(12L), eq(4L), eq(4L))).thenReturn(1);
        when(jdbcTemplate.queryForObject(org.mockito.ArgumentMatchers.contains("FROM jti_blacklist"), eq(Integer.class),
                eq("jti-1"))).thenReturn(0);
        OAuthClient client = new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of("token_exchange"), Set.of("ragforge-admin-api"), Set.of("rag:search"), "ACTIVE");

        assertThat(statusService().introspection(claims, client)).containsEntry("active", false);
    }

    private AccessTokenVerifier verifier() {
        return new AccessTokenVerifier(jwksProvider);
    }

    private TokenStatusService statusService() {
        return new TokenStatusService(jdbcTemplate, properties);
    }

    private JWTClaimsSet activeClaims() {
        return claims(properties.getIssuer(), Instant.now().plusSeconds(60), "sid-1", 4, "jti-1");
    }

    private JWTClaimsSet claims(String issuer, Instant expiresAt, String sessionId, long sessionVersion, String jti) {
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience("careermate-api")
                .subject("user:12")
                .expirationTime(Date.from(expiresAt))
                .jwtID(jti)
                .claim("principal_type", "user")
                .claim("user_id", 12L)
                .claim("platform_role", "USER")
                .claim("rag_role", "USER")
                .claim("scopes", List.of("rag:search"))
                .claim("session_id", sessionId)
                .claim("session_version", sessionVersion)
                .build();
    }

    private String sign(JWTClaimsSet claims, RSAKey key) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }
}
