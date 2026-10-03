package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.oauth.OAuthClientProvisioningService;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** Provisioning endpoint. The public reverse proxy must deny /internal/clients. */
@RestController
public class InternalClientController {

    private final ClientAuthenticator authenticator;
    private final OAuthClientProvisioningService provisioningService;
    private final String provisionerClientId;

    public InternalClientController(ClientAuthenticator authenticator,
            OAuthClientProvisioningService provisioningService,
            @Value("${auth.internal.provisioner-client-id:}") String provisionerClientId) {
        this.authenticator = authenticator;
        this.provisioningService = provisioningService;
        this.provisionerClientId = provisionerClientId;
    }

    @PostMapping("/internal/clients")
    public Map<String, Object> register(@RequestHeader("X-Client-Id") String callerId,
            @RequestHeader("X-Client-Assertion-Type") String assertionType,
            @RequestHeader("X-Client-Assertion") String assertion,
            HttpServletRequest servletRequest,
            @RequestBody Registration request) {
        requireInternalAddress(servletRequest);
        requireProvisioner(callerId, assertionType, assertion);
        validate(request);
        provisioningService.upsert(callerId, request);
        return Map.of("client_id", request.clientId(), "status", "ACTIVE");
    }

    @DeleteMapping("/internal/clients/{clientId}")
    public ResponseEntity<Void> delete(@RequestHeader("X-Client-Id") String callerId,
            @RequestHeader("X-Client-Assertion-Type") String assertionType,
            @RequestHeader("X-Client-Assertion") String assertion,
            HttpServletRequest servletRequest,
            @PathVariable String clientId) {
        requireInternalAddress(servletRequest);
        requireProvisioner(callerId, assertionType, assertion);
        if (!validName(clientId)) {
            throw new AuthException(400, "CLIENT_ID_INVALID", "client_id is invalid");
        }
        if (clientId.equals(provisionerClientId)) {
            throw new AuthException(403, "CLIENT_PROVISIONING_DENIED", "provisioner client cannot be deleted");
        }
        provisioningService.delete(callerId, clientId);
        return ResponseEntity.noContent().build();
    }

    private void requireProvisioner(String callerId, String assertionType, String assertion) {
        if (!StringUtils.hasText(provisionerClientId) || !provisionerClientId.equals(callerId)) {
            throw new AuthException(403, "CLIENT_PROVISIONING_DENIED", "client is not allowed to provision clients");
        }
        OAuthClient caller = authenticator.authenticate(callerId, assertionType, assertion);
        if (!provisionerClientId.equals(caller.clientId())) {
            throw new AuthException(403, "CLIENT_PROVISIONING_DENIED", "client is not allowed to provision clients");
        }
    }

    private void requireInternalAddress(HttpServletRequest request) {
        try {
            InetAddress address = InetAddress.getByName(request.getRemoteAddr());
            if (address.isLoopbackAddress() || address.isSiteLocalAddress()) {
                return;
            }
        } catch (Exception ignored) {
            // Unknown remote addresses are not internal.
        }
        throw new AuthException(404, "CLIENT_ENDPOINT_NOT_FOUND", "endpoint not found");
    }

    private void validate(Registration request) {
        if (request == null || !validName(request.clientId())
                || request.allowedAudiences() == null || request.allowedAudiences().isEmpty()
                || request.allowedAudiences().stream().anyMatch(audience -> !validName(audience))
                || request.scopes() == null || request.scopes().isEmpty()
                || request.scopes().stream().anyMatch(scope -> !StringUtils.hasText(scope) || scope.length() > 128)
                || request.grantTypes() == null || !request.grantTypes().equals(List.of("token-exchange"))) {
            throw new AuthException(400, "CLIENT_REGISTRATION_INVALID", "client registration is invalid");
        }
        try {
            URI uri = URI.create(request.jwksUri());
            if (!("https".equals(uri.getScheme()) || "http".equals(uri.getScheme()))
                    || uri.getHost() == null || uri.getRawUserInfo() != null) {
                throw new IllegalArgumentException();
            }
        } catch (Exception ex) {
            throw new AuthException(400, "CLIENT_JWKS_URI_INVALID", "jwks_uri must be an HTTP(S) URL");
        }
    }

    private boolean validName(String name) {
        return name != null && name.matches("[a-z][a-z0-9-]{0,63}");
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status()).body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    public record Registration(@JsonProperty("client_id") String clientId,
            @JsonProperty("jwks_uri") String jwksUri,
            @JsonProperty("allowed_audiences") Set<String> allowedAudiences,
            Set<String> scopes,
            @JsonProperty("grant_types") List<String> grantTypes) {
    }
}
