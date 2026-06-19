package com.careermate.authgw.oauth;

import com.careermate.authgw.crypto.JwksProvider;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("dev")
public class DevLocalJwksAssertionSource {

    private final JwksProvider jwksProvider;

    public DevLocalJwksAssertionSource(JwksProvider jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    public JWKSource<SecurityContext> jwkSource() {
        return new ImmutableJWKSet<>(jwksProvider.publicJwkSet());
    }
}
