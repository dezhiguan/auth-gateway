package com.careermate.authgw.web;

import com.careermate.authgw.auth.AccessTokenVerifier;
import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.audit.AuditLogService;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** 协议同意：新用户注册后 / 老用户协议升级时补签。 */
@RestController
public class TermsController {

    private final AccessTokenVerifier accessTokenVerifier;
    private final AuthUserRepository userRepository;
    private final AuditLogService auditLogService;

    public TermsController(
            AccessTokenVerifier accessTokenVerifier,
            AuthUserRepository userRepository,
            AuditLogService auditLogService) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
    }

    @PostMapping(value = "/auth/users/me/terms-acceptance", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> acceptTerms(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody TermsRequest request) {
        JWTClaimsSet claims = accessTokenVerifier.verify(authorization);
        Object userId = claims.getClaim("user_id");
        if (userId == null) throw new AuthException(401, "USER_ID_MISSING", "token 中缺少 user_id");
        long uid = ((Number) userId).longValue();
        String version = (request.termsVersion() != null && !request.termsVersion().isBlank())
                ? request.termsVersion() : "1.0";
        userRepository.updateTermsAcceptance(uid, version);
        auditLogService.info("terms.accepted", uid, null, Map.of("version", version));
        return Map.of("accepted", true, "termsVersion", version);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    public record TermsRequest(String termsVersion) {}
}
