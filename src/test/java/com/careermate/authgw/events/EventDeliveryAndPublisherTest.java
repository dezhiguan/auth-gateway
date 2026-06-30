package com.careermate.authgw.events;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.careermate.authgw.auth.AuthProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

@ExtendWith(MockitoExtension.class)
class EventDeliveryAndPublisherTest {

    @Mock JdbcTemplate jdbcTemplate;
    @Mock EventOutboxRepository outboxRepository;
    @Mock EventDelivery eventDelivery;
    @Mock ResultSet resultSet;
    @Mock Environment environment;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void deliverySignsRequestWithHmacAndMarksSingleAttemptSuccess() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        EventDelivery delivery = new EventDelivery(objectMapper, builder);
        Map<String, Object> envelope = Map.of("event_id", "evt-1", "type", "session.revoked");
        server.expect(requestTo("https://subscriber.example/events"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(request -> {
                    byte[] body = ((MockClientHttpRequest) request).getBodyAsBytes();
                    assertThat(request.getHeaders().getFirst("X-Auth-Event-Signature"))
                            .isEqualTo(hmac("secret-value", body));
                    assertThat(request.getHeaders().getFirst("X-Auth-Event-Timestamp")).isNotBlank();
                    assertThat(new String(body, StandardCharsets.UTF_8)).contains("evt-1");
                })
                .andRespond(withSuccess());

        EventDelivery.DeliveryResult result = delivery.deliver("https://subscriber.example/events", "secret-value", envelope);

        assertThat(result.delivered()).isTrue();
        assertThat(result.attempts()).isEqualTo(1);
        server.verify();
    }

    @Test
    void deliveryRetriesAndSucceedsOnSecondAttempt() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        EventDelivery delivery = new EventDelivery(objectMapper, builder);
        server.expect(requestTo("https://subscriber.example/events")).andRespond(withServerError());
        server.expect(requestTo("https://subscriber.example/events")).andRespond(withSuccess());

        EventDelivery.DeliveryResult result = delivery.deliver("https://subscriber.example/events", "secret-value", Map.of("event_id", "evt-1"));

        assertThat(result.delivered()).isTrue();
        assertThat(result.attempts()).isEqualTo(2);
        server.verify();
    }

    @Test
    void deliveryFailsAfterMaxAttempts() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        EventDelivery delivery = new EventDelivery(objectMapper, builder);
        server.expect(times(3), requestTo("https://subscriber.example/events")).andRespond(withServerError());

        EventDelivery.DeliveryResult result = delivery.deliver("https://subscriber.example/events", "secret-value", Map.of("event_id", "evt-1"));

        assertThat(result.delivered()).isFalse();
        assertThat(result.attempts()).isEqualTo(3);
        assertThat(result.lastError()).isNotBlank();
        server.verify();
    }

    @Test
    @SuppressWarnings("unchecked")
    void subscriptionGuardRejectsMissingAndTooShortSecrets() throws Exception {
        AuthProperties properties = new AuthProperties();
        EventSubscriptionGuard guard = new EventSubscriptionGuard(jdbcTemplate, properties);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class))).thenAnswer(invocation -> {
            RowMapper<?> mapper = invocation.getArgument(1);
            when(resultSet.getString("subscriber")).thenReturn("ragforge");
            when(resultSet.getString("hmac_secret")).thenReturn("");
            return List.of(mapper.mapRow(resultSet, 0));
        });

        assertThatThrownBy(() -> guard.onApplicationEvent(null))
                .isInstanceOfSatisfying(IllegalStateException.class,
                        ex -> assertThat(ex.getMessage()).contains("hmac_secret missing"));

        when(jdbcTemplate.query(anyString(), any(RowMapper.class))).thenAnswer(invocation -> {
            RowMapper<?> mapper = invocation.getArgument(1);
            when(resultSet.getString("subscriber")).thenReturn("ragforge");
            when(resultSet.getString("hmac_secret")).thenReturn("short");
            return List.of(mapper.mapRow(resultSet, 0));
        });
        assertThatThrownBy(() -> guard.onApplicationEvent(null))
                .isInstanceOfSatisfying(IllegalStateException.class,
                        ex -> assertThat(ex.getMessage()).contains("too short"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void publisherContinuesWhenOneSubscriptionDeliveryFails() throws Exception {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq("session.revoked"))).thenAnswer(invocation -> {
            RowMapper<?> mapper = invocation.getArgument(1);
            when(resultSet.getString("subscriber")).thenReturn("sub-a");
            when(resultSet.getString("endpoint_url")).thenReturn("https://a.example/events");
            when(resultSet.getString("hmac_secret")).thenReturn("secret-a");
            Object first = mapper.mapRow(resultSet, 0);
            when(resultSet.getString("subscriber")).thenReturn("sub-b");
            when(resultSet.getString("endpoint_url")).thenReturn("https://b.example/events");
            when(resultSet.getString("hmac_secret")).thenReturn("secret-b");
            Object second = mapper.mapRow(resultSet, 1);
            return List.of(first, second);
        });
        when(eventDelivery.deliver(eq("https://a.example/events"), eq("secret-a"), any()))
                .thenReturn(EventDelivery.DeliveryResult.failed(3, "boom"));
        when(eventDelivery.deliver(eq("https://b.example/events"), eq("secret-b"), any()))
                .thenReturn(EventDelivery.DeliveryResult.delivered(1));

        new EventPublisher(jdbcTemplate, outboxRepository, eventDelivery)
                .publish("session.revoked", Map.of("session_id", "sid-1"));

        verify(outboxRepository).markFailed(anyString(), eq(3), eq("boom"));
        verify(outboxRepository).markDelivered(anyString(), eq(1), any(Instant.class));
        verify(eventDelivery).deliver(eq("https://a.example/events"), eq("secret-a"), any());
        verify(eventDelivery).deliver(eq("https://b.example/events"), eq("secret-b"), any());
    }

    private String hmac(String secret, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return "sha256=" + HexFormat.of().formatHex(mac.doFinal(body));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
