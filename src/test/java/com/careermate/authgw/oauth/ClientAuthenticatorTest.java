package com.careermate.authgw.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthProperties;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.OAuthClientRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class ClientAuthenticatorTest {

    @Mock OAuthClientRepository clientRepository;
    @Mock JdbcTemplate jdbcTemplate;
    @Mock DevLocalJwksAssertionSource devLocalJwksAssertionSource;

    private AuthProperties properties;
    private RSAKey key;

    @BeforeEach
    void setUp() throws Exception {
        properties = new AuthProperties();
        properties.getDev().setAllowLocalJwksClientAssertions(true);
        key = new RSAKeyGenerator(2048).keyID("client-key").generate();
    }

    @Test
    void rejectsMissingClientId() {
        assertThatThrownBy(() -> authenticator().authenticate("", ClientAuthenticator.ASSERTION_TYPE, "assertion"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_ASSERTION_REQUIRED"));
    }

    @Test
    void rejectsUnknownClient() {
        when(clientRepository.findById("client")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authenticator().authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_NOT_FOUND"));
    }

    @Test
    void rejectsInactiveClientAndUnsupportedAuthMethod() {
        when(clientRepository.findById("client")).thenReturn(Optional.of(client("DISABLED", "private_key_jwt", null)));
        assertThatThrownBy(() -> authenticator().authenticate("client", ClientAuthenticator.ASSERTION_TYPE, "assertion"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_AUTH_METHOD_INVALID"));

        when(clientRepository.findById("client2")).thenReturn(Optional.of(client("ACTIVE", "client_secret_basic", null)));
        assertThatThrownBy(() -> authenticator().authenticate("client2", ClientAuthenticator.ASSERTION_TYPE, "assertion"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_AUTH_METHOD_INVALID"));
    }

    @Test
    void rejectsMissingJwksUriWhenLocalJwksDisabled() throws Exception {
        properties.getDev().setAllowLocalJwksClientAssertions(false);
        when(clientRepository.findById("client")).thenReturn(Optional.of(client("ACTIVE", "private_key_jwt", null)));

        assertThatThrownBy(() -> authenticator().authenticate("client", ClientAuthenticator.ASSERTION_TYPE, assertion("client", "client",
                properties.getTokenEndpointAudience(), "jti-1", Instant.now(), Instant.now().plusSeconds(60), key)))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_JWKS_MISSING"));
    }

    @Test
    void rejectsExpiredAssertionAudienceMismatchSubjectMismatchAndMissingJti() throws Exception {
        when(clientRepository.findById("client")).thenReturn(Optional.of(client("ACTIVE", "private_key_jwt", null)));
        when(devLocalJwksAssertionSource.jwkSource()).thenReturn(new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK())));

        assertAuthCode(assertion("client", "client", properties.getTokenEndpointAudience(), "jti-expired",
                        Instant.now().minusSeconds(120), Instant.now().minusSeconds(60), key),
                "CLIENT_ASSERTION_EXPIRED");
        assertAuthCode(assertion("client", "client", "wrong-aud", "jti-aud",
                        Instant.now(), Instant.now().plusSeconds(60), key),
                "CLIENT_ASSERTION_AUDIENCE_INVALID");
        assertAuthCode(assertion("other", "client", properties.getTokenEndpointAudience(), "jti-sub",
                        Instant.now(), Instant.now().plusSeconds(60), key),
                "CLIENT_ASSERTION_SUBJECT_INVALID");
        assertAuthCode(assertion("client", "client", properties.getTokenEndpointAudience(), null,
                        Instant.now(), Instant.now().plusSeconds(60), key),
                "CLIENT_ASSERTION_JTI_REQUIRED");
    }

    @Test
    void rejectsAssertionTtlLongerThanTenMinutes() throws Exception {
        when(clientRepository.findById("client")).thenReturn(Optional.of(client("ACTIVE", "private_key_jwt", null)));
        when(devLocalJwksAssertionSource.jwkSource()).thenReturn(new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK())));

        assertAuthCode(assertion("client", "client", properties.getTokenEndpointAudience(), "jti-long",
                        Instant.now(), Instant.now().plusSeconds(601), key),
                "CLIENT_ASSERTION_TTL_INVALID");
    }

    @Test
    void rejectsJtiReplayAndAcceptsFirstUse() throws Exception {
        OAuthClient client = client("ACTIVE", "private_key_jwt", null);
        when(clientRepository.findById("client")).thenReturn(Optional.of(client));
        when(devLocalJwksAssertionSource.jwkSource()).thenReturn(new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK())));
        String assertion = assertion("client", "client", properties.getTokenEndpointAudience(), "jti-1",
                Instant.now(), Instant.now().plusSeconds(60), key);
        when(jdbcTemplate.update(org.mockito.ArgumentMatchers.contains("INSERT INTO jti_blacklist"), eq("jti-1"), any())).thenReturn(1);

        assertThat(authenticator().authenticate("client", ClientAuthenticator.ASSERTION_TYPE, assertion)).isSameAs(client);

        when(jdbcTemplate.update(org.mockito.ArgumentMatchers.contains("INSERT INTO jti_blacklist"), eq("jti-2"), any())).thenReturn(0);
        String replayed = assertion("client", "client", properties.getTokenEndpointAudience(), "jti-2",
                Instant.now(), Instant.now().plusSeconds(60), key);
        assertThatThrownBy(() -> authenticator().authenticate("client", ClientAuthenticator.ASSERTION_TYPE, replayed))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_ASSERTION_REPLAYED"));
    }

    private void assertAuthCode(String assertion, String code) {
        assertThatThrownBy(() -> authenticator().authenticate("client", ClientAuthenticator.ASSERTION_TYPE, assertion))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo(code));
    }

    private ClientAuthenticator authenticator() {
        return new ClientAuthenticator(clientRepository, jdbcTemplate, properties, Optional.of(devLocalJwksAssertionSource));
    }

    private OAuthClient client(String status, String method, String jwksUri) {
        return new OAuthClient("client", "client", method, jwksUri,
                Set.of("client_credentials"), Set.of("careermate-api"), Set.of("rag:search"), status);
    }

    private String assertion(String issuer, String subject, String audience, String jti, Instant issuedAt, Instant expiresAt, RSAKey signingKey)
            throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt));
        if (jti != null) {
            builder.jwtID(jti);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(), builder.build());
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }
}
