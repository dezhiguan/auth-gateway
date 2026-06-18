package com.careermate.authgw.web;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenPair;
import com.careermate.authgw.auth.TokenService;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthTokenController {

    private final ClientAuthenticator clientAuthenticator;
    private final AccessTokenVerifier accessTokenVerifier;
    private final TokenService tokenService;

    public AuthTokenController(
            ClientAuthenticator clientAuthenticator,
            AccessTokenVerifier accessTokenVerifier,
            TokenService tokenService) {
        this.clientAuthenticator = clientAuthenticator;
        this.accessTokenVerifier = accessTokenVerifier;
        this.tokenService = tokenService;
    }

    @PostMapping(value = "/auth/token/refresh", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public TokenResponse refresh(
            @RequestParam("refresh_token") String refreshToken,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        OAuthClient client = clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        TokenPair tokens = tokenService.refresh(refreshToken, client);
        return new TokenResponse(tokens.accessToken(), tokens.refreshToken(), tokens.tokenType(), tokens.expiresIn());
    }

    @PostMapping("/auth/logout")
    public Map<String, Object> logout(@RequestHeader(name = "Authorization", required = false) String authorization) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        tokenService.logout(claims);
        return Map.of("revoked", true);
    }

    @PostMapping(value = "/auth/logout-all", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> logoutAll(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody LogoutAllRequest request) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        tokenService.logoutAll(claims, request.password());
        return Map.of("revoked", true);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    @JsonPropertyOrder({"access_token", "refresh_token", "token_type", "expires_in"})
    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn) {
    }

    public record LogoutAllRequest(String password) {
    }
}
