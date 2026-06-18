package com.careermate.authgw.auth;

import com.careermate.authgw.crypto.JwksProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Component;

@Component
public class AccessTokenVerifier {

    private final JwksProvider jwksProvider;

    public AccessTokenVerifier(JwksProvider jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    public JWTClaimsSet verify(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new AuthException(401, "ACCESS_TOKEN_REQUIRED", "Bearer access token is required");
        }
        String token = authorizationHeader.substring("Bearer ".length()).trim();
        return verifyToken(token);
    }

    public JWTClaimsSet verifyToken(String token) {
        try {
            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            JWSKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(
                    JWSAlgorithm.RS256,
                    new ImmutableJWKSet<>(jwksProvider.publicJwkSet()));
            processor.setJWSKeySelector(selector);
            return processor.process(token, null);
        } catch (Exception ex) {
            throw new AuthException(401, "ACCESS_TOKEN_INVALID", "access token is invalid");
        }
    }
}
