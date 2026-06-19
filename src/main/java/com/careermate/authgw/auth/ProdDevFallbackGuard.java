package com.careermate.authgw.auth;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("prod")
public class ProdDevFallbackGuard {

    private final AuthProperties properties;

    public ProdDevFallbackGuard(AuthProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void validate() {
        if (properties.getDev().isAllowLocalJwksClientAssertions()) {
            throw new IllegalStateException("auth.dev.allow-local-jwks-client-assertions must be false in prod");
        }
    }
}
