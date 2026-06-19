package com.careermate.authgw.web;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenStatusService;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.oauth.ConsentService;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuthConsentController {

    private final AccessTokenVerifier accessTokenVerifier;
    private final TokenStatusService tokenStatusService;
    private final ConsentService consentService;
    private final ClientAuthenticator clientAuthenticator;

    public OAuthConsentController(
            AccessTokenVerifier accessTokenVerifier,
            TokenStatusService tokenStatusService,
            ConsentService consentService,
            ClientAuthenticator clientAuthenticator) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.tokenStatusService = tokenStatusService;
        this.consentService = consentService;
        this.clientAuthenticator = clientAuthenticator;
    }

    @PostMapping("/oauth/consents")
    public ConsentResponse create(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody CreateConsentRequest request) {
        JWTClaimsSet claims = verifiedUserClaims(authorization);
        ConsentService.ConsentRecord consent = consentService.create(
                claims,
                request.clientPrincipalId(),
                request.scopes(),
                request.allowedKbIds(),
                request.expiresInSeconds());
        return ConsentResponse.from(consent);
    }

    @GetMapping("/oauth/consents")
    public List<ConsentResponse> list(@RequestHeader(name = "Authorization", required = false) String authorization) {
        JWTClaimsSet claims = verifiedUserClaims(authorization);
        return consentService.list(claims).stream().map(ConsentResponse::from).toList();
    }

    @PostMapping("/oauth/consents/{id}/revoke")
    public Map<String, Object> revoke(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("id") String consentId) {
        JWTClaimsSet claims = verifiedUserClaims(authorization);
        consentService.revoke(claims, consentId);
        return Map.of("revoked", true);
    }

    @PostMapping(value = "/oauth/delegation-token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public DelegationTokenResponse delegationToken(
            @RequestParam("consent_id") String consentId,
            @RequestParam("requested_audience") String requestedAudience,
            @RequestParam("requested_scopes") String requestedScopes,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        OAuthClient client = clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        ConsentService.DelegationToken token = consentService.issueDelegationToken(
                client,
                consentId,
                requestedAudience,
                consentService.parseScopes(requestedScopes));
        return new DelegationTokenResponse(
                token.accessToken(),
                token.issuedTokenType(),
                token.tokenType(),
                token.expiresIn(),
                token.scope());
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    private JWTClaimsSet verifiedUserClaims(String authorization) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        tokenStatusService.requireActiveUserAccessToken(claims);
        return claims;
    }

    public record CreateConsentRequest(
            @JsonProperty("client_principal_id") String clientPrincipalId,
            Set<String> scopes,
            @JsonProperty("allowed_kb_ids") List<Long> allowedKbIds,
            @JsonProperty("expires_in_seconds") Long expiresInSeconds) {
    }

    @JsonPropertyOrder({"consent_id", "client_principal_id", "scopes", "allowed_kb_ids", "expires_at", "revoked_at", "active"})
    public record ConsentResponse(
            @JsonProperty("consent_id") String consentId,
            @JsonProperty("client_principal_id") String clientPrincipalId,
            Set<String> scopes,
            @JsonProperty("allowed_kb_ids") List<Long> allowedKbIds,
            @JsonProperty("expires_at") String expiresAt,
            @JsonProperty("revoked_at") String revokedAt,
            boolean active) {
        static ConsentResponse from(ConsentService.ConsentRecord consent) {
            return new ConsentResponse(
                    consent.consentId(),
                    consent.clientPrincipalId(),
                    consent.scopes(),
                    consent.allowedKbIds(),
                    consent.expiresAt().toString(),
                    consent.revokedAt() == null ? null : consent.revokedAt().toString(),
                    consent.active());
        }
    }

    @JsonPropertyOrder({"access_token", "issued_token_type", "token_type", "expires_in", "scope"})
    public record DelegationTokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("issued_token_type") String issuedTokenType,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn,
            String scope) {
    }
}
