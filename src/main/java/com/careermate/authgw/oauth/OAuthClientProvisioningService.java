package com.careermate.authgw.oauth;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.web.InternalClientController.Registration;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OAuthClientProvisioningService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final AuditLogService auditLogService;

    public OAuthClientProvisioningService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper,
            AuditLogService auditLogService) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public void upsert(String callerId, Registration request) {
        String audiences = json(request.allowedAudiences());
        String scopes = json(request.scopes());
        String grants = json(Set.of(TokenExchangeService.GRANT_TYPE));
        int changed = jdbcTemplate.update("""
                INSERT INTO oauth_clients(client_id, client_name, auth_method, jwks_uri,
                                          allowed_grant_types, allowed_audiences, allowed_scopes, status, keel_managed)
                VALUES (?, ?, 'private_key_jwt', ?, ?::jsonb, ?::jsonb, ?::jsonb, 'ACTIVE', TRUE)
                ON CONFLICT (client_id) DO UPDATE SET
                    jwks_uri = EXCLUDED.jwks_uri,
                    allowed_grant_types = EXCLUDED.allowed_grant_types,
                    allowed_audiences = EXCLUDED.allowed_audiences,
                    allowed_scopes = EXCLUDED.allowed_scopes,
                    status = 'ACTIVE'
                WHERE oauth_clients.keel_managed = TRUE
                """, request.clientId(), request.clientId(), request.jwksUri(), grants, audiences, scopes);
        if (changed == 0) {
            throw new AuthException(409, "CLIENT_NOT_MANAGED", "existing client is not managed by Keel");
        }
        auditLogService.high("oauth_client.upsert", null, callerId, Map.of("client_id", request.clientId()));
    }

    @Transactional
    public void delete(String callerId, String clientId) {
        jdbcTemplate.update("DELETE FROM oauth_clients WHERE client_id = ? AND keel_managed = TRUE", clientId);
        auditLogService.high("oauth_client.delete", null, callerId, Map.of("client_id", clientId));
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("failed to encode client registration", ex);
        }
    }
}
