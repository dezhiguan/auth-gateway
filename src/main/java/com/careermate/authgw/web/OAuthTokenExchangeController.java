package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.oauth.TokenExchangeService;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuthTokenExchangeController {

    private final ClientAuthenticator clientAuthenticator;
    private final TokenExchangeService tokenExchangeService;

    public OAuthTokenExchangeController(ClientAuthenticator clientAuthenticator, TokenExchangeService tokenExchangeService) {
        this.clientAuthenticator = clientAuthenticator;
        this.tokenExchangeService = tokenExchangeService;
    }

    @PostMapping(value = "/oauth/token-exchange", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public TokenExchangeResponse exchange(
            @RequestParam("grant_type") String grantType,
            @RequestParam("subject_token") String subjectToken,
            @RequestParam("subject_token_type") String subjectTokenType,
            @RequestParam("requested_audience") String requestedAudience,
            @RequestParam("requested_scopes") String requestedScopes,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        OAuthClient client = clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        TokenExchangeService.TokenExchangeResult result = tokenExchangeService.exchange(
                client, grantType, subjectToken, subjectTokenType, requestedAudience, requestedScopes);
        return new TokenExchangeResponse(
                result.accessToken(),
                result.issuedTokenType(),
                result.tokenType(),
                result.expiresIn(),
                result.scope());
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    @JsonPropertyOrder({"access_token", "issued_token_type", "token_type", "expires_in", "scope"})
    public record TokenExchangeResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("issued_token_type") String issuedTokenType,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn,
            String scope) {
    }
}
