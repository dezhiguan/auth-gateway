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
