package com.careermate.authgw.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private String issuer = "https://auth.careermate.cn";
    private String tokenEndpointAudience = "https://auth.careermate.cn/oauth/token";
    private long accessTokenTtlSeconds = 900;
    private long refreshTokenTtlSeconds = 604800;
    /** 勾选"记住我"时 refresh token 的 TTL（默认 30 天），跨旋转继承（滑动窗口）。 */
    private long rememberRefreshTtlSeconds = 2592000;
    /**
     * refresh token 旋转宽限期（秒）：已旋转的 token 在该窗口内被再次使用视作并发双刷
     * （多标签页/弱网重试），补发新令牌而非按重放灭族；0 表示关闭宽限、恢复严格一次性。
     */
    private long refreshRotationGraceSeconds = 60;
    private long exchangeTokenTtlSeconds = 600;
    private Dev dev = new Dev();
    private Events events = new Events();

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

    public long getRememberRefreshTtlSeconds() {
        return rememberRefreshTtlSeconds;
    }

    public void setRememberRefreshTtlSeconds(long rememberRefreshTtlSeconds) {
        this.rememberRefreshTtlSeconds = rememberRefreshTtlSeconds;
    }

    public long getRefreshRotationGraceSeconds() {
        return refreshRotationGraceSeconds;
    }

    public void setRefreshRotationGraceSeconds(long refreshRotationGraceSeconds) {
        this.refreshRotationGraceSeconds = refreshRotationGraceSeconds;
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

    public Events getEvents() {
        return events;
    }

    public void setEvents(Events events) {
        this.events = events;
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

    public static class Events {
        private boolean devAllowEmptySecret;

        public boolean isDevAllowEmptySecret() {
            return devAllowEmptySecret;
        }

        public void setDevAllowEmptySecret(boolean devAllowEmptySecret) {
            this.devAllowEmptySecret = devAllowEmptySecret;
        }
    }
}
