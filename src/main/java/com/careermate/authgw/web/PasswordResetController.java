package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.PasswordResetService;
import com.careermate.authgw.auth.TokenPair;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PasswordResetController {

    private final PasswordResetService passwordResetService;
    private final ClientAuthenticator clientAuthenticator;

    public PasswordResetController(PasswordResetService passwordResetService, ClientAuthenticator clientAuthenticator) {
        this.passwordResetService = passwordResetService;
        this.clientAuthenticator = clientAuthenticator;
    }

    @PostMapping("/auth/password/reset/init")
    public ResetInitResponse init(@RequestBody ResetInitRequest request) {
        PasswordResetService.ResetInitResult result = passwordResetService.init(request.account());
        return new ResetInitResponse(result.maskedPhone(), result.ticketRequired());
    }

    @PostMapping("/auth/password/reset/verify")
    public ResetVerifyResponse verify(@RequestBody ResetVerifyRequest request) {
        return new ResetVerifyResponse(passwordResetService.verify(request.account(), request.code()));
    }

    @PostMapping("/auth/password/reset/confirm")
    public TokenResponse confirm(@RequestBody ResetConfirmRequest request) {
        OAuthClient client = clientAuthenticator.authenticate(
                request.clientId(),
                request.clientAssertionType(),
                request.clientAssertion());
        TokenPair tokens = passwordResetService.confirm(
                request.resetTicket(),
                request.newPassword(),
                client,
                request.targetAud());
        return new TokenResponse(tokens.accessToken(), tokens.refreshToken(), tokens.tokenType(), tokens.expiresIn());
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    public record ResetInitRequest(String account) {
    }

    @JsonPropertyOrder({"masked_phone", "ticket_required"})
    public record ResetInitResponse(
            @JsonProperty("masked_phone") String maskedPhone,
            @JsonProperty("ticket_required") boolean ticketRequired) {
    }

    public record ResetVerifyRequest(String account, String code) {
    }

    @JsonPropertyOrder({"reset_ticket"})
    public record ResetVerifyResponse(@JsonProperty("reset_ticket") String resetTicket) {
    }

    public record ResetConfirmRequest(
            @JsonProperty("reset_ticket") String resetTicket,
            @JsonProperty("new_password") String newPassword,
            @JsonProperty("target_aud") String targetAud,
            @JsonProperty("client_id") String clientId,
            @JsonProperty("client_assertion_type") String clientAssertionType,
            @JsonProperty("client_assertion") String clientAssertion) {
    }

    @JsonPropertyOrder({"access_token", "refresh_token", "token_type", "expires_in"})
    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn) {
    }
}
