package com.careermate.authgw.oauth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthProperties;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenIssuer;
import com.careermate.authgw.auth.TokenStatusService;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class TokenExchangeService {

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String EXCHANGED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final AccessTokenVerifier accessTokenVerifier;
    private final TokenStatusService tokenStatusService;
    private final TokenIssuer tokenIssuer;
    private final AuthProperties authProperties;
    private final AuditLogService auditLogService;

    public TokenExchangeService(
            AccessTokenVerifier accessTokenVerifier,
            TokenStatusService tokenStatusService,
            TokenIssuer tokenIssuer,
            AuthProperties authProperties,
            AuditLogService auditLogService) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.tokenStatusService = tokenStatusService;
        this.tokenIssuer = tokenIssuer;
        this.authProperties = authProperties;
        this.auditLogService = auditLogService;
    }

    public TokenExchangeResult exchange(
            OAuthClient client,
            String grantType,
            String subjectToken,
            String subjectTokenType,
            String requestedAudience,
            String requestedScopes) {
        if (!GRANT_TYPE.equals(grantType)) {
            throw new AuthException(400, "GRANT_TYPE_UNSUPPORTED", "grant_type is unsupported");
        }
        if (!ACCESS_TOKEN_TYPE.equals(subjectTokenType) || !StringUtils.hasText(subjectToken)) {
            throw new AuthException(400, "SUBJECT_TOKEN_INVALID", "subject_token is invalid");
        }
        if (!client.allowedGrantTypes().contains(GRANT_TYPE)) {
            throw new AuthException(403, "GRANT_TYPE_DENIED", "client is not allowed to use token exchange");
        }

        JWTClaimsSet subjectClaims = accessTokenVerifier.verifyToken(subjectToken);
        tokenStatusService.requireActiveUserAccessToken(subjectClaims);
        if (!subjectAudienceAllowed(subjectClaims, client)) {
            throw new AuthException(403, "SUBJECT_AUDIENCE_DENIED", "subject token audience is not allowed for client");
        }
        if (!client.allowedAudiences().contains(requestedAudience)) {
            throw new AuthException(403, "AUDIENCE_NOT_ALLOWED", "client is not allowed to request audience");
        }

        Set<String> scopes = parseScopes(requestedScopes);
        Set<String> userScopes = userHeldScopes(subjectClaims);
        if (scopes.isEmpty() || !client.allowedScopes().containsAll(scopes) || !userScopes.containsAll(scopes)) {
            throw new AuthException(403, "SCOPE_NOT_ALLOWED", "requested scopes are not allowed");
        }

        String accessToken = tokenIssuer.issueExchangedToken(subjectClaims, client, requestedAudience, scopes);
        auditLogService.info("token_exchange.success", userId(subjectClaims), client.clientId(), Map.of(
                "requested_audience", requestedAudience,
                "requested_scopes", String.join(" ", scopes),
                "subject_token", subjectToken));
        return new TokenExchangeResult(
                accessToken,
                EXCHANGED_TOKEN_TYPE,
                "Bearer",
                authProperties.getExchangeTokenTtlSeconds(),
                String.join(" ", scopes));
    }

    private boolean subjectAudienceAllowed(JWTClaimsSet claims, OAuthClient client) {
        return claims.getAudience() != null
                && claims.getAudience().stream().anyMatch(client.allowedAudiences()::contains);
    }

    private Set<String> parseScopes(String requestedScopes) {
        Set<String> scopes = new LinkedHashSet<>();
        if (!StringUtils.hasText(requestedScopes)) {
            return scopes;
        }
        for (String scope : requestedScopes.trim().split("\\s+")) {
            if (StringUtils.hasText(scope)) {
                scopes.add(scope);
            }
        }
        return scopes;
    }

    private Set<String> userHeldScopes(JWTClaimsSet claims) {
        Set<String> scopes = new LinkedHashSet<>();
        try {
            for (Object scope : claims.getListClaim("scopes")) {
                scopes.add(String.valueOf(scope));
            }
        } catch (Exception ignored) {
            // Invalid or absent scopes are treated as empty.
        }
        if ("ADMIN".equalsIgnoreCase(String.valueOf(claims.getClaim("platform_role")))) {
            scopes.add("rag:search");
        }
        return scopes;
    }

    private Long userId(JWTClaimsSet claims) {
        Object value = claims.getClaim("user_id");
        if (value instanceof Number number) {
            return number.longValue();
        }
        return value == null ? null : Long.parseLong(String.valueOf(value));
    }

    public record TokenExchangeResult(
            String accessToken,
            String issuedTokenType,
            String tokenType,
            long expiresIn,
            String scope) {
    }
}
