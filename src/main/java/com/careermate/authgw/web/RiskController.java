package com.careermate.authgw.web;

import com.careermate.authgw.risk.RiskService;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RiskController {

    private final RiskService riskService;

    public RiskController(RiskService riskService) {
        this.riskService = riskService;
    }

    @PostMapping("/risk/login-failure")
    public Map<String, Object> loginFailure(@RequestBody LoginFailureRequest request) {
        RiskService.RiskDecision decision = riskService.recordLoginFailure(request.account(), request.ip());
        return Map.of(
                "captcha_required", decision.captchaRequired(),
                "ip_limited", decision.ipLimited(),
                "lock_ttl_seconds", decision.lockTtlSeconds());
    }

    @PostMapping("/risk/location-warning")
    public Map<String, Object> locationWarning(@RequestBody LocationWarningRequest request) {
        return riskService.locationWarning(request.userId(), request.lastRegion(), request.currentRegion());
    }

    public record LoginFailureRequest(String account, String ip) {
    }

    public record LocationWarningRequest(
            @JsonProperty("user_id") long userId,
            @JsonProperty("last_region") String lastRegion,
            @JsonProperty("current_region") String currentRegion) {
    }
}
