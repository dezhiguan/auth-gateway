package com.careermate.authgw.oauth;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthProperties;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.OAuthClientRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URL;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class ClientAuthenticator {

    public static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final OAuthClientRepository clientRepository;
    private final JdbcTemplate jdbcTemplate;
    private final AuthProperties properties;
    private final Optional<DevLocalJwksAssertionSource> devLocalJwksAssertionSource;

    public ClientAuthenticator(
            OAuthClientRepository clientRepository,
            JdbcTemplate jdbcTemplate,
            AuthProperties properties,
            Optional<DevLocalJwksAssertionSource> devLocalJwksAssertionSource) {
        this.clientRepository = clientRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
        this.devLocalJwksAssertionSource = devLocalJwksAssertionSource;
    }

    public OAuthClient authenticate(String clientId, String assertionType, String assertion) {
        if (!StringUtils.hasText(clientId) || !ASSERTION_TYPE.equals(assertionType) || !StringUtils.hasText(assertion)) {
            throw new AuthException(401, "CLIENT_ASSERTION_REQUIRED", "client_assertion form fields are required");
        }

        OAuthClient client = clientRepository.findById(clientId)
                .orElseThrow(() -> new AuthException(401, "CLIENT_NOT_FOUND", "client not found"));
        if (!"ACTIVE".equalsIgnoreCase(client.status()) || !"private_key_jwt".equalsIgnoreCase(client.authMethod())) {
            throw new AuthException(401, "CLIENT_AUTH_METHOD_INVALID", "client authentication method is invalid");
        }

        JWTClaimsSet claims = verifyAssertion(client, assertion);
        validateClaims(clientId, claims);
        rememberJti(claims);
        return client;
    }

    private JWTClaimsSet verifyAssertion(OAuthClient client, String assertion) {
        try {
            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> jwkSource = resolveJwkSource(client);
            JWSKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
            processor.setJWSKeySelector(selector);
            return processor.process(assertion, null);
        } catch (BadJOSEException ex) {
            throw new AuthException(401, "CLIENT_ASSERTION_INVALID", "client_assertion rejected");
        } catch (Exception ex) {
            throw new AuthException(401, "CLIENT_ASSERTION_INVALID", "client_assertion verification failed");
        }
    }

    private JWKSource<SecurityContext> resolveJwkSource(OAuthClient client) throws Exception {
        if (properties.getDev().isAllowLocalJwksClientAssertions() && devLocalJwksAssertionSource.isPresent()) {
            return devLocalJwksAssertionSource.get().jwkSource();
        }
        if (!StringUtils.hasText(client.jwksUri())) {
            throw new AuthException(401, "CLIENT_JWKS_MISSING", "client jwks_uri is missing");
        }
        return new RemoteJWKSet<>(new URL(client.jwksUri()));
    }

    private void validateClaims(String clientId, JWTClaimsSet claims) {
        if (!clientId.equals(claims.getIssuer()) || !clientId.equals(claims.getSubject())) {
            throw new AuthException(401, "CLIENT_ASSERTION_SUBJECT_INVALID", "client_assertion iss/sub must match client_id");
        }
        if (claims.getAudience() == null || !claims.getAudience().contains(properties.getTokenEndpointAudience())) {
            throw new AuthException(401, "CLIENT_ASSERTION_AUDIENCE_INVALID", "client_assertion aud is invalid");
        }
        if (!StringUtils.hasText(claims.getJWTID())) {
            throw new AuthException(401, "CLIENT_ASSERTION_JTI_REQUIRED", "client_assertion jti is required");
        }
        Date expiration = claims.getExpirationTime();
        Date issueTime = claims.getIssueTime();
        if (expiration == null || expiration.before(new Date())) {
            throw new AuthException(401, "CLIENT_ASSERTION_EXPIRED", "client_assertion is expired");
        }
        if (issueTime != null && expiration.toInstant().isAfter(issueTime.toInstant().plusSeconds(600))) {
            throw new AuthException(401, "CLIENT_ASSERTION_TTL_INVALID", "client_assertion exp must be within 10 minutes");
        }
    }

    private void rememberJti(JWTClaimsSet claims) {
        int inserted = jdbcTemplate.update("""
                        INSERT INTO jti_blacklist(jti, expires_at)
                        VALUES (?, ?)
                        ON CONFLICT (jti) DO NOTHING
                        """,
                claims.getJWTID(), Date.from(claims.getExpirationTime().toInstant()));
        if (inserted == 0) {
            throw new AuthException(401, "CLIENT_ASSERTION_REPLAYED", "client_assertion jti replayed");
        }
        jdbcTemplate.update("DELETE FROM jti_blacklist WHERE expires_at < ?", Date.from(Instant.now()));
    }
}
