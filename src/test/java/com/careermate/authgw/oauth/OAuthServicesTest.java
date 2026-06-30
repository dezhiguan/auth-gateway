package com.careermate.authgw.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthProperties;
import com.careermate.authgw.auth.AuthUser;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.OAuthClientRepository;
import com.careermate.authgw.auth.TokenIssuer;
import com.careermate.authgw.auth.TokenStatusService;
import com.careermate.authgw.events.EventPublisher;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

@ExtendWith(MockitoExtension.class)
class OAuthServicesTest {

    @Mock OAuthClientRepository clientRepository;
    @Mock JdbcTemplate jdbcTemplate;
    @Mock AccessTokenVerifier accessTokenVerifier;
    @Mock TokenStatusService tokenStatusService;
    @Mock TokenIssuer tokenIssuer;
    @Mock AuditLogService auditLogService;
    @Mock AuthUserRepository userRepository;
    @Mock EventPublisher eventPublisher;

    private final AuthProperties properties = new AuthProperties();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void clientAuthenticatorRequiresAssertionFields() {
        assertThatThrownBy(() -> clientAuthenticator().authenticate("client", ClientAuthenticator.ASSERTION_TYPE, ""))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_ASSERTION_REQUIRED"));
    }

    @Test
    void clientAuthenticatorRejectsMissingJwksUri() {
        OAuthClient client = client(null, Set.of("rag:search"));
        when(clientRepository.findById("ragforge-admin-backend")).thenReturn(Optional.of(client));

        assertThatThrownBy(() -> clientAuthenticator().authenticate("ragforge-admin-backend",
                ClientAuthenticator.ASSERTION_TYPE, "not-a-jwt"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CLIENT_JWKS_MISSING"));
    }

    @Test
    void tokenExchangeIssuesTokenWhenClientSubjectAndScopesAreAllowed() throws Exception {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search"));
        JWTClaimsSet subjectClaims = new JWTClaimsSet.Builder()
                .subject("user:12")
                .audience("careermate-api")
                .claim("user_id", 12L)
                .claim("scopes", List.of("rag:search"))
                .build();
        when(accessTokenVerifier.verifyToken("subject-token")).thenReturn(subjectClaims);
        when(tokenIssuer.issueExchangedToken(subjectClaims, client, "ragforge-admin-api", Set.of("rag:search")))
                .thenReturn("exchanged-token");

        TokenExchangeService.TokenExchangeResult result = tokenExchangeService().exchange(client,
                TokenExchangeService.GRANT_TYPE,
                "subject-token",
                TokenExchangeService.ACCESS_TOKEN_TYPE,
                "ragforge-admin-api",
                "rag:search");

        assertThat(result.accessToken()).isEqualTo("exchanged-token");
        assertThat(result.scope()).isEqualTo("rag:search");
        verify(tokenStatusService).requireActiveUserAccessToken(subjectClaims);
    }

    @Test
    void tokenExchangeRejectsScopesNotHeldBySubject() {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search", "rag:admin:read"));
        JWTClaimsSet subjectClaims = new JWTClaimsSet.Builder()
                .audience("careermate-api")
                .claim("user_id", 12L)
                .claim("scopes", List.of("rag:search"))
                .build();
        when(accessTokenVerifier.verifyToken("subject-token")).thenReturn(subjectClaims);

        assertThatThrownBy(() -> tokenExchangeService().exchange(client,
                TokenExchangeService.GRANT_TYPE,
                "subject-token",
                TokenExchangeService.ACCESS_TOKEN_TYPE,
                "ragforge-admin-api",
                "rag:admin:read"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SCOPE_NOT_ALLOWED"));
    }

    @Test
    void tokenExchangeRejectsUnsupportedGrantTypeAndMissingSubjectToken() {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search"));

        assertThatThrownBy(() -> tokenExchangeService().exchange(client, "password",
                "subject-token", TokenExchangeService.ACCESS_TOKEN_TYPE, "ragforge-admin-api", "rag:search"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("GRANT_TYPE_UNSUPPORTED"));
        assertThatThrownBy(() -> tokenExchangeService().exchange(client, TokenExchangeService.GRANT_TYPE,
                "", TokenExchangeService.ACCESS_TOKEN_TYPE, "ragforge-admin-api", "rag:search"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SUBJECT_TOKEN_INVALID"));
    }

    @Test
    void tokenExchangeRejectsClientNotAllowedForGrant() {
        OAuthClient client = new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of("refresh_token"), Set.of("careermate-api"), Set.of("rag:search"), "ACTIVE");

        assertThatThrownBy(() -> tokenExchangeService().exchange(client, TokenExchangeService.GRANT_TYPE,
                "subject-token", TokenExchangeService.ACCESS_TOKEN_TYPE, "careermate-api", "rag:search"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("GRANT_TYPE_DENIED"));
    }

    @Test
    void tokenExchangeRejectsSubjectAudienceNotAllowedForClient() {
        OAuthClient client = new OAuthClient("client", "client", "private_key_jwt", null,
                Set.of(TokenExchangeService.GRANT_TYPE), Set.of("ragforge-admin-api"), Set.of("rag:search"), "ACTIVE");
        JWTClaimsSet subjectClaims = new JWTClaimsSet.Builder()
                .audience("careermate-api")
                .claim("user_id", 12L)
                .claim("scopes", List.of("rag:search"))
                .build();
        when(accessTokenVerifier.verifyToken("subject-token")).thenReturn(subjectClaims);

        assertThatThrownBy(() -> tokenExchangeService().exchange(client, TokenExchangeService.GRANT_TYPE,
                "subject-token", TokenExchangeService.ACCESS_TOKEN_TYPE, "ragforge-admin-api", "rag:search"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SUBJECT_AUDIENCE_DENIED"));
    }

    @Test
    void tokenExchangeRejectsRequestedAudienceNotAllowed() {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search"));
        JWTClaimsSet subjectClaims = new JWTClaimsSet.Builder()
                .audience("careermate-api")
                .claim("user_id", 12L)
                .claim("scopes", List.of("rag:search"))
                .build();
        when(accessTokenVerifier.verifyToken("subject-token")).thenReturn(subjectClaims);

        assertThatThrownBy(() -> tokenExchangeService().exchange(client, TokenExchangeService.GRANT_TYPE,
                "subject-token", TokenExchangeService.ACCESS_TOKEN_TYPE, "unknown-api", "rag:search"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("AUDIENCE_NOT_ALLOWED"));
    }

    @Test
    void tokenExchangeRejectsScopesBeyondClientAllowedScopes() {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search"));
        JWTClaimsSet subjectClaims = new JWTClaimsSet.Builder()
                .audience("careermate-api")
                .claim("user_id", 12L)
                .claim("scopes", List.of("rag:search", "rag:admin:read"))
                .build();
        when(accessTokenVerifier.verifyToken("subject-token")).thenReturn(subjectClaims);

        assertThatThrownBy(() -> tokenExchangeService().exchange(client, TokenExchangeService.GRANT_TYPE,
                "subject-token", TokenExchangeService.ACCESS_TOKEN_TYPE, "ragforge-admin-api", "rag:admin:read"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SCOPE_NOT_ALLOWED"));
    }

    @Test
    void consentParseScopesDeduplicatesWhitespaceSeparatedScopes() {
        assertThat(consentService().parseScopes(" rag:search  rag:search rag:admin:read "))
                .containsExactly("rag:search", "rag:admin:read");
    }

    @Test
    @SuppressWarnings("unchecked")
    void consentCreateRejectsScopeOutsideClientAllowedScopes() {
        when(clientRepository.findById("ragforge-admin-backend")).thenReturn(Optional.of(client("https://example.com/jwks.json", Set.of("rag:search"))));
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();

        assertThatThrownBy(() -> consentService().create(claims, "ragforge-admin-backend",
                Set.of("rag:admin:read"), List.of(100L), 600L))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SCOPE_NOT_ALLOWED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void consentCreatePersistsAllowedKbIdsAndReturnsCreatedRecord() {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search", "rag:admin:read"));
        when(clientRepository.findById("ragforge-admin-backend")).thenReturn(Optional.of(client));
        ConsentService.ConsentRecord created = new ConsentService.ConsentRecord(
                "consent-created", 12, "ragforge-admin-backend", Set.of("rag:search"),
                List.of(100L, 101L), Instant.now().plusSeconds(600), null);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), org.mockito.ArgumentMatchers.startsWith("consent_")))
                .thenReturn(List.of(created));
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();

        ConsentService.ConsentRecord result = consentService().create(claims, "ragforge-admin-backend",
                Set.of("rag:search"), List.of(100L, 101L), 600L);

        assertThat(result).isSameAs(created);
        ArgumentCaptor<String> scopesJson = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> kbJson = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).update(org.mockito.ArgumentMatchers.contains("INSERT INTO agent_consents"),
                org.mockito.ArgumentMatchers.startsWith("consent_"),
                eq(12L),
                eq("ragforge-admin-backend"),
                scopesJson.capture(),
                kbJson.capture(),
                any());
        assertThat(scopesJson.getValue()).contains("rag:search");
        assertThat(kbJson.getValue()).isEqualTo("[100,101]");
    }

    @Test
    @SuppressWarnings("unchecked")
    void consentListQueriesOnlyCurrentUser() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();
        ConsentService.ConsentRecord row = new ConsentService.ConsentRecord(
                "consent-1", 12, "ragforge-admin-backend", Set.of("rag:search"),
                List.of(100L), Instant.now().plusSeconds(600), null);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq(12L))).thenReturn(List.of(row));

        assertThat(consentService().list(claims)).containsExactly(row);
    }

    @Test
    @SuppressWarnings("unchecked")
    void consentIssueDelegationTokenValidatesConsentAndReturnsBearerToken() {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search"));
        ConsentService.ConsentRecord consent = new ConsentService.ConsentRecord(
                "consent-1", 12, "ragforge-admin-backend", Set.of("rag:search"),
                List.of(100L), Instant.now().plusSeconds(300), null);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), any())).thenReturn(List.of(consent));
        when(userRepository.findById(12)).thenReturn(Optional.of(new AuthUser(12, "phone", null, "amy", "pwd", "USER", 5, "ACTIVE")));
        when(tokenIssuer.issueDelegationToken(12, "consent-1", client, "ragforge-admin-api", Set.of("rag:search"), List.of(100L), 5))
                .thenReturn("delegated-token");

        ConsentService.DelegationToken token = consentService()
                .issueDelegationToken(client, "consent-1", "ragforge-admin-api", Set.of("rag:search"));

        assertThat(token.accessToken()).isEqualTo("delegated-token");
        assertThat(token.tokenType()).isEqualTo("Bearer");
    }

    @Test
    @SuppressWarnings("unchecked")
    void consentRevokePublishesEventWhenRowUpdated() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();
        when(jdbcTemplate.update(anyString(), eq("consent-1"), eq(12L))).thenReturn(1);

        consentService().revoke(claims, "consent-1");

        verify(eventPublisher).publish("consent.revoked", java.util.Map.of("consent_id", "consent-1", "user_id", 12L));
    }

    @Test
    void consentRevokeRejectsMissingConsent() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("user_id", 12L).build();
        when(jdbcTemplate.update(anyString(), eq("missing"), eq(12L))).thenReturn(0);

        assertThatThrownBy(() -> consentService().revoke(claims, "missing"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CONSENT_NOT_FOUND"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void consentIssueDelegationTokenRejectsExpiredRevokedClientMismatchAndScopeOverflow() {
        OAuthClient client = client("https://example.com/jwks.json", Set.of("rag:search", "rag:admin:read"));
        ConsentService.ConsentRecord expired = new ConsentService.ConsentRecord(
                "consent-1", 12, "ragforge-admin-backend", Set.of("rag:search"),
                List.of(100L), Instant.now().minusSeconds(1), null);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("consent-1"))).thenReturn(List.of(expired));
        assertThatThrownBy(() -> consentService().issueDelegationToken(client, "consent-1", "ragforge-admin-api", Set.of("rag:search")))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CONSENT_REVOKED"));

        ConsentService.ConsentRecord revoked = new ConsentService.ConsentRecord(
                "consent-2", 12, "ragforge-admin-backend", Set.of("rag:search"),
                List.of(100L), Instant.now().plusSeconds(600), Instant.now());
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("consent-2"))).thenReturn(List.of(revoked));
        assertThatThrownBy(() -> consentService().issueDelegationToken(client, "consent-2", "ragforge-admin-api", Set.of("rag:search")))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CONSENT_REVOKED"));

        ConsentService.ConsentRecord otherClient = new ConsentService.ConsentRecord(
                "consent-3", 12, "other-client", Set.of("rag:search"),
                List.of(100L), Instant.now().plusSeconds(600), null);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("consent-3"))).thenReturn(List.of(otherClient));
        assertThatThrownBy(() -> consentService().issueDelegationToken(client, "consent-3", "ragforge-admin-api", Set.of("rag:search")))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("CONSENT_CLIENT_MISMATCH"));

        ConsentService.ConsentRecord scoped = new ConsentService.ConsentRecord(
                "consent-4", 12, "ragforge-admin-backend", Set.of("rag:search"),
                List.of(100L), Instant.now().plusSeconds(600), null);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("consent-4"))).thenReturn(List.of(scoped));
        assertThatThrownBy(() -> consentService().issueDelegationToken(client, "consent-4", "ragforge-admin-api", Set.of("rag:admin:read")))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("SCOPE_NOT_ALLOWED"));
    }

    private ClientAuthenticator clientAuthenticator() {
        return new ClientAuthenticator(clientRepository, jdbcTemplate, properties, Optional.empty());
    }

    private TokenExchangeService tokenExchangeService() {
        return new TokenExchangeService(accessTokenVerifier, tokenStatusService, tokenIssuer, properties, auditLogService);
    }

    private ConsentService consentService() {
        return new ConsentService(jdbcTemplate, objectMapper, clientRepository, userRepository, tokenIssuer, eventPublisher, auditLogService);
    }

    private static OAuthClient client(String jwksUri, Set<String> scopes) {
        return new OAuthClient("ragforge-admin-backend", "RAGForge", "private_key_jwt", jwksUri,
                Set.of(TokenExchangeService.GRANT_TYPE, "refresh_token"),
                Set.of("careermate-api", "ragforge-admin-api"), scopes, "ACTIVE");
    }
}
