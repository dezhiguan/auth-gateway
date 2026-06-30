package com.careermate.authgw.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.crypto.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class TokenIssuerTest {

    @Mock JwtSigner jwtSigner;
    @Mock JdbcTemplate jdbcTemplate;
    @Mock TokenHasher tokenHasher;

    private final AuthProperties properties = new AuthProperties();

    @Test
    void issueUserTokensStoresSessionAndRefreshTokenAndSignsUserClaims() throws Exception {
        AuthUser user = new AuthUser(12, "phone", null, "amy", "pwd", "ADMIN", 4, "ACTIVE");
        OAuthClient client = client(Set.of("ragforge-admin-api"));
        when(tokenHasher.sha256Hex(anyString())).thenReturn("refresh-hash");
        when(jwtSigner.sign(any(JWTClaimsSet.class))).thenReturn("signed-access");

        TokenPair pair = issuer().issueUserTokens(user, client, "ragforge-admin-api");

        assertThat(pair.accessToken()).isEqualTo("signed-access");
        assertThat(pair.refreshToken()).startsWith("rt_");
        assertThat(pair.tokenType()).isEqualTo("Bearer");
        verify(jdbcTemplate).update(org.mockito.ArgumentMatchers.contains("INSERT INTO auth_sessions"),
                org.mockito.ArgumentMatchers.startsWith("sid_"), org.mockito.ArgumentMatchers.eq(12L),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.eq("ragforge-admin-api"),
                org.mockito.ArgumentMatchers.eq(4L));
        verify(jdbcTemplate).update(org.mockito.ArgumentMatchers.contains("INSERT INTO refresh_tokens"),
                org.mockito.ArgumentMatchers.eq("refresh-hash"), org.mockito.ArgumentMatchers.startsWith("rtf_"),
                org.mockito.ArgumentMatchers.startsWith("sid_"), any());
        ArgumentCaptor<JWTClaimsSet> claims = ArgumentCaptor.forClass(JWTClaimsSet.class);
        verify(jwtSigner).sign(claims.capture());
        assertThat(claims.getValue().getSubject()).isEqualTo("user:12");
        assertThat(claims.getValue().getStringClaim("rag_role")).isEqualTo("ADMIN");
        assertThat(claims.getValue().getStringListClaim("scopes")).containsExactly("rag:admin:read", "rag:admin:write");
    }

    @Test
    void issueRotatedRefreshRejectsDisallowedAudience() {
        AuthUser user = new AuthUser(12, "phone", null, "amy", "pwd", "USER", 4, "ACTIVE");

        assertThatThrownBy(() -> issuer().issueRotatedRefresh(user, client(Set.of("careermate-api")),
                "ragforge-admin-api", "sid", "family"))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.code()).isEqualTo("AUDIENCE_NOT_ALLOWED"));
    }

    @Test
    void issueExchangedTokenCopiesSubjectClaimsAndScopes() throws Exception {
        JWTClaimsSet subject = new JWTClaimsSet.Builder()
                .subject("user:99")
                .claim("principal_type", "user")
                .claim("user_id", 99L)
                .claim("platform_role", "USER")
                .claim("rag_role", "USER")
                .claim("rag_readable_kb_ids", List.of(1L))
                .claim("rag_writable_kb_ids", List.of())
                .claim("session_id", "sid")
                .claim("session_version", 2L)
                .build();
        when(jwtSigner.sign(any(JWTClaimsSet.class))).thenReturn("exchanged");

        String token = issuer().issueExchangedToken(subject, client(Set.of("ragforge-admin-api")),
                "ragforge-admin-api", Set.of("rag:admin:read"));

        assertThat(token).isEqualTo("exchanged");
        ArgumentCaptor<JWTClaimsSet> claims = ArgumentCaptor.forClass(JWTClaimsSet.class);
        verify(jwtSigner).sign(claims.capture());
        assertThat(claims.getValue().getStringClaim("azp")).isEqualTo("ragforge-admin-backend");
        assertThat(claims.getValue().getStringListClaim("scopes")).containsExactly("rag:admin:read");
    }

    @Test
    void issueDelegationTokenCreatesAgentSubject() throws Exception {
        when(jwtSigner.sign(any(JWTClaimsSet.class))).thenReturn("delegated");

        String token = issuer().issueDelegationToken(21, "consent-1", client(Set.of("ragforge-admin-api")),
                "ragforge-admin-api", Set.of("rag:search"), List.of(10L), 3);

        assertThat(token).isEqualTo("delegated");
        ArgumentCaptor<JWTClaimsSet> claims = ArgumentCaptor.forClass(JWTClaimsSet.class);
        verify(jwtSigner).sign(claims.capture());
        assertThat(claims.getValue().getSubject()).isEqualTo("agent:ragforge-admin-backend:user:21");
        assertThat(claims.getValue().getLongClaim("delegated_user_id")).isEqualTo(21L);
    }

    private TokenIssuer issuer() {
        return new TokenIssuer(jwtSigner, jdbcTemplate, properties, tokenHasher);
    }

    private static OAuthClient client(Set<String> audiences) {
        return new OAuthClient("ragforge-admin-backend", "RAGForge", "private_key_jwt", null,
                Set.of("password", "refresh_token"), audiences,
                Set.of("rag:admin:read", "rag:admin:write", "rag:search"), "ACTIVE");
    }
}
