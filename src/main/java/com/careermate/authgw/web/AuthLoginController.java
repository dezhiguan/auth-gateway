package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.LoginService;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenPair;
import com.careermate.authgw.oauth.ClientAuthenticator;
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
public class AuthLoginController {

    private final ClientAuthenticator clientAuthenticator;
    private final LoginService loginService;

    public AuthLoginController(ClientAuthenticator clientAuthenticator, LoginService loginService) {
        this.clientAuthenticator = clientAuthenticator;
        this.loginService = loginService;
    }

    @PostMapping(value = "/auth/login/password", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public LoginResponse loginPassword(
            @RequestParam String account,
            @RequestParam String password,
            @RequestParam("target_aud") String targetAud,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        OAuthClient client = clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        TokenPair tokens = loginService.loginPassword(account, password, targetAud, client);
        return new LoginResponse(tokens.accessToken(), tokens.refreshToken(), tokens.tokenType(), tokens.expiresIn());
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        if (ex.status() == 423) {
            return ResponseEntity.status(ex.status())
                    .body(Map.of("error", ex.code(), "message", ex.getMessage(), "captcha_required", true));
        }
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    @JsonPropertyOrder({"access_token", "refresh_token", "token_type", "expires_in"})
    public record LoginResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn) {
    }
}
