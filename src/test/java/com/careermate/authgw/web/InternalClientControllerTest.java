package com.careermate.authgw.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.oauth.OAuthClientProvisioningService;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

@ExtendWith(MockitoExtension.class)
class InternalClientControllerTest {

    @Mock ClientAuthenticator authenticator;
    @Mock OAuthClientProvisioningService provisioningService;

    private InternalClientController controller() {
        return new InternalClientController(authenticator, provisioningService, "keel-server");
    }

    private MockHttpServletRequest internalRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.8");
        return request;
    }

    private InternalClientController.Registration registration() {
        return new InternalClientController.Registration("ops-copilot", "https://keel.example/agents/ops-copilot/jwks.json",
                Set.of("keel-api", "ops-copilot", "askdb"), Set.of("agent:invoke"), List.of("token-exchange"));
    }

    @Test
    void repeatedRegistrationUpdatesManagedClient() {
        when(authenticator.authenticate("keel-server", ClientAuthenticator.ASSERTION_TYPE, "signed"))
                .thenReturn(new OAuthClient("keel-server", "Keel", "private_key_jwt", "https://keel.example/jwks",
                        Set.of(), Set.of(), Set.of(), "ACTIVE"));

        assertThat(controller().register("keel-server", ClientAuthenticator.ASSERTION_TYPE, "signed", internalRequest(), registration()))
                .containsEntry("status", "ACTIVE");
        assertThat(controller().register("keel-server", ClientAuthenticator.ASSERTION_TYPE, "signed", internalRequest(), registration()))
                .containsEntry("status", "ACTIVE");
        verify(provisioningService, times(2)).upsert("keel-server", registration());
    }

    @Test
    void publicAddressAndWrongCallerAreDenied() {
        MockHttpServletRequest publicRequest = new MockHttpServletRequest();
        publicRequest.setRemoteAddr("8.8.8.8");
        assertThatThrownBy(() -> controller().register("keel-server", ClientAuthenticator.ASSERTION_TYPE,
                "signed", publicRequest, registration()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.status()).isEqualTo(404));
        assertThatThrownBy(() -> controller().register("careermate-backend", ClientAuthenticator.ASSERTION_TYPE,
                "signed", internalRequest(), registration()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.status()).isEqualTo(403));
    }

    @Test
    void existingUnmanagedClientCannotBeOverwritten() {
        when(authenticator.authenticate("keel-server", ClientAuthenticator.ASSERTION_TYPE, "signed"))
                .thenReturn(new OAuthClient("keel-server", "Keel", "private_key_jwt", "https://keel.example/jwks",
                        Set.of(), Set.of(), Set.of(), "ACTIVE"));
        doThrow(new AuthException(409, "CLIENT_NOT_MANAGED", "existing client is not managed by Keel"))
                .when(provisioningService).upsert("keel-server", registration());

        assertThatThrownBy(() -> controller().register("keel-server", ClientAuthenticator.ASSERTION_TYPE,
                "signed", internalRequest(), registration()))
                .isInstanceOfSatisfying(AuthException.class, ex -> assertThat(ex.status()).isEqualTo(409));
    }
}
