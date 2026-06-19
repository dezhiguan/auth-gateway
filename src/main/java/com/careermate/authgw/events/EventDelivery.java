package com.careermate.authgw.events;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class EventDelivery {

    private static final int MAX_ATTEMPTS = 3;
    private static final long[] BACKOFF_MILLIS = {1_000L, 2_000L, 4_000L};

    private final ObjectMapper objectMapper;
    private final RestClient restClient;

    public EventDelivery(ObjectMapper objectMapper, RestClient.Builder restClientBuilder) {
        this.objectMapper = objectMapper;
        this.restClient = restClientBuilder.build();
    }

    public DeliveryResult deliver(String endpointUrl, String hmacSecret, Map<String, Object> envelope) {
        byte[] body = body(envelope);
        String signature = signature(hmacSecret, body);
        String timestamp = Long.toString(Instant.now().getEpochSecond());
        Exception lastException = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                restClient.post()
                        .uri(endpointUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Auth-Event-Signature", signature)
                        .header("X-Auth-Event-Timestamp", timestamp)
                        .body(body)
                        .retrieve()
                        .toBodilessEntity();
                return DeliveryResult.delivered(attempt);
            } catch (Exception ex) {
                lastException = ex;
                if (attempt < MAX_ATTEMPTS) {
                    sleep(BACKOFF_MILLIS[attempt - 1]);
                }
            }
        }
        return DeliveryResult.failed(MAX_ATTEMPTS, errorMessage(lastException));
    }

    private byte[] body(Map<String, Object> envelope) {
        try {
            return objectMapper.writeValueAsBytes(envelope);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("failed to serialize auth event envelope", ex);
        }
    }

    private String signature(String hmacSecret, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(body);
            return "sha256=" + HexFormat.of().formatHex(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("failed to sign auth event", ex);
        }
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while retrying auth event delivery", ex);
        }
    }

    private String errorMessage(Exception ex) {
        if (ex == null) {
            return "unknown delivery failure";
        }
        String message = ex.getMessage();
        return message == null || message.isBlank() ? ex.getClass().getName() : message;
    }

    public record DeliveryResult(boolean delivered, int attempts, String lastError) {
        public static DeliveryResult delivered(int attempts) {
            return new DeliveryResult(true, attempts, null);
        }

        public static DeliveryResult failed(int attempts, String lastError) {
            return new DeliveryResult(false, attempts, lastError);
        }
    }
}
