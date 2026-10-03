package com.careermate.authgw.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.web.InternalClientController.Registration;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class OAuthClientProvisioningServiceTest {

    @Mock JdbcTemplate jdbcTemplate;
    @Mock AuditLogService auditLogService;

    private OAuthClientProvisioningService service() {
        return new OAuthClientProvisioningService(jdbcTemplate, new ObjectMapper(), auditLogService);
    }

    private Registration registration() {
        return new Registration("ops-copilot", "https://keel.example/agents/ops-copilot/jwks.json",
                Set.of("keel-api", "ops-copilot", "askdb"), Set.of("agent:invoke"), List.of("token-exchange"));
    }

    @Test
    void upsertReplacesWholeAudienceSetAndAuditsEachAttempt() {
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);

        service().upsert("keel-server", registration());
        service().upsert("keel-server", registration());

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate, times(2)).update(sql.capture(), any(Object[].class));
        assertThat(sql.getValue()).contains("allowed_audiences = EXCLUDED.allowed_audiences")
                .contains("oauth_clients.keel_managed = TRUE");
        verify(auditLogService, times(2)).high(org.mockito.ArgumentMatchers.eq("oauth_client.upsert"),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.eq("keel-server"), any());
    }

    @Test
    void upsertCannotTakeOverExistingNonKeelClient() {
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(0);

        assertThatThrownBy(() -> service().upsert("keel-server", registration()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.status()).isEqualTo(409));
    }
}
