package com.careermate.authgw.web;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenStatusService;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserInfoController {

    private final AccessTokenVerifier accessTokenVerifier;
    private final TokenStatusService tokenStatusService;
    private final ClientAuthenticator clientAuthenticator;

    public UserInfoController(
            AccessTokenVerifier accessTokenVerifier,
            TokenStatusService tokenStatusService,
            ClientAuthenticator clientAuthenticator) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.tokenStatusService = tokenStatusService;
        this.clientAuthenticator = clientAuthenticator;
    }

    @GetMapping("/userinfo")
    public Map<String, Object> userInfo(@RequestHeader(name = "Authorization", required = false) String authorization) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        return tokenStatusService.userInfo(claims);
    }

    @PostMapping(value = "/oauth/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> introspect(
            @RequestParam String token,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        OAuthClient client = clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        try {
            JWTClaimsSet claims = accessTokenVerifier.verifyToken(token);
            return tokenStatusService.introspection(claims, client);
        } catch (AuthException ex) {
            return Map.of("active", false);
        }
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }
}
