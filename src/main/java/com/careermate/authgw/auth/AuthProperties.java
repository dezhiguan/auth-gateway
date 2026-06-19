package com.careermate.authgw.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private String issuer = "https://auth.careermate.cn";
    private String tokenEndpointAudience = "https://auth.careermate.cn/oauth/token";
    private long accessTokenTtlSeconds = 900;
    private long refreshTokenTtlSeconds = 604800;
    private long exchangeTokenTtlSeconds = 600;
    private Dev dev = new Dev();

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getTokenEndpointAudience() {
        return tokenEndpointAudience;
    }

    public void setTokenEndpointAudience(String tokenEndpointAudience) {
        this.tokenEndpointAudience = tokenEndpointAudience;
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) {
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    public void setRefreshTokenTtlSeconds(long refreshTokenTtlSeconds) {
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public long getExchangeTokenTtlSeconds() {
        return exchangeTokenTtlSeconds;
    }

    public void setExchangeTokenTtlSeconds(long exchangeTokenTtlSeconds) {
        this.exchangeTokenTtlSeconds = exchangeTokenTtlSeconds;
    }

    public Dev getDev() {
        return dev;
    }

    public void setDev(Dev dev) {
        this.dev = dev;
    }

    public static class Dev {
        private boolean allowLocalJwksClientAssertions;

        public boolean isAllowLocalJwksClientAssertions() {
            return allowLocalJwksClientAssertions;
        }

        public void setAllowLocalJwksClientAssertions(boolean allowLocalJwksClientAssertions) {
            this.allowLocalJwksClientAssertions = allowLocalJwksClientAssertions;
        }
    }
}
