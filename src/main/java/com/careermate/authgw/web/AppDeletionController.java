package com.careermate.authgw.web;

import com.careermate.authgw.audit.AuditLogService;
import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AppMembership;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.MembershipRepository;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * 应用级注销：只退某个 App（careermate / ragforge），不动共享身份与其他 App 准入。
 *
 * <p>凭 Bearer access token 识别用户即可操作；调用方（如 CareerMate 账号设置）在其自己界面
 * 完成短信+确认字的 step-up，再委托本接口标记 membership。注销 30 天内可恢复、风险可控。</p>
 */
@RestController
public class AppDeletionController {

    private static final Set<String> ALLOWED_APPS = Set.of("careermate", "ragforge");

    private final AccessTokenVerifier accessTokenVerifier;
    private final MembershipRepository membershipRepository;
    private final AuditLogService auditLogService;

    public AppDeletionController(
            AccessTokenVerifier accessTokenVerifier,
            MembershipRepository membershipRepository,
            AuditLogService auditLogService) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.membershipRepository = membershipRepository;
        this.auditLogService = auditLogService;
    }

    @PostMapping("/auth/apps/{app}/deletion-request")
    public Map<String, Object> requestDeletion(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("app") String app) {
        String normalizedApp = requireAllowedApp(app);
        long userId = currentUserId(authorization);
        Instant scheduledAt = membershipRepository.markPendingDeletion(userId, normalizedApp);
        if (scheduledAt == null) {
            throw new AuthException(404, "APP_MEMBERSHIP_NOT_FOUND", "当前账号未开通该应用，无需注销");
        }
        auditLogService.high("app.deletion.requested", userId, null, Map.of("app", normalizedApp));
        return Map.of("app", normalizedApp, "deletionScheduledAt", scheduledAt.toString());
    }

    @DeleteMapping("/auth/apps/{app}/deletion-request")
    public Map<String, Object> cancelDeletion(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("app") String app) {
        String normalizedApp = requireAllowedApp(app);
        long userId = currentUserId(authorization);
        int updated = membershipRepository.cancelDeletion(userId, normalizedApp);
        if (updated != 1) {
            throw new AuthException(400, "NOT_PENDING_DELETION", "该应用当前未处于注销冷静期");
        }
        auditLogService.info("app.deletion.cancelled", userId, null, Map.of("app", normalizedApp));
        return Map.of("app", normalizedApp, "status", "ACTIVE");
    }

    @GetMapping("/auth/apps/{app}/deletion-status")
    public Map<String, Object> deletionStatus(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable("app") String app) {
        String normalizedApp = requireAllowedApp(app);
        long userId = currentUserId(authorization);
        AppMembership m = membershipRepository.find(userId, normalizedApp).orElse(null);
        String status = m == null ? "NONE" : m.status();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("app", normalizedApp);
        body.put("status", status);
        body.put("pendingDeletion", "PENDING_DELETION".equalsIgnoreCase(status));
        return body;
    }

    private String requireAllowedApp(String app) {
        String normalized = app == null ? "" : app.trim().toLowerCase();
        if (!ALLOWED_APPS.contains(normalized)) {
            throw new AuthException(400, "APP_NOT_SUPPORTED", "不支持的应用");
        }
        return normalized;
    }

    private long currentUserId(String authorization) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        Object userId = claims.getClaim("user_id");
        if (userId == null) {
            throw new AuthException(401, "ACCESS_TOKEN_INVALID", "登录状态已失效，请重新登录");
        }
        return Long.parseLong(String.valueOf(userId));
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }
}
