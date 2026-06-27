package com.careermate.authgw.web;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.CredentialService;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * 凭证管理入口（Bearer 保护）。用户身份来自 access token 的 user_id claim。
 */
@RestController
public class CredentialController {

    private final AccessTokenVerifier accessTokenVerifier;
    private final CredentialService credentialService;

    public CredentialController(AccessTokenVerifier accessTokenVerifier, CredentialService credentialService) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.credentialService = credentialService;
    }

    @PostMapping(value = "/auth/credential/set-password", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> setPassword(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody SetPasswordRequest request) {
        long userId = currentUserId(authorization);
        credentialService.setPassword(userId, request.oldPassword(), request.newPassword());
        return Map.of("success", true);
    }

    @PostMapping(value = "/auth/credential/bind-email", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> bindEmail(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody BindEmailRequest request) {
        long userId = currentUserId(authorization);
        credentialService.bindEmail(userId, request.email(), request.password());
        return Map.of("success", true);
    }

    @PostMapping(value = "/auth/credential/set-username", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> setUsername(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody SetUsernameRequest request) {
        long userId = currentUserId(authorization);
        credentialService.setUsername(userId, request.username());
        return Map.of("success", true);
    }

    private long currentUserId(String authorization) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        Object userId = claims.getClaim("user_id");
        if (userId == null) {
            throw new AuthException(401, "ACCESS_TOKEN_INVALID", "access token is invalid");
        }
        return Long.parseLong(String.valueOf(userId));
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    public record SetPasswordRequest(String oldPassword, String newPassword) {
    }

    public record BindEmailRequest(String email, String password) {
    }

    public record SetUsernameRequest(String username) {
    }
}
