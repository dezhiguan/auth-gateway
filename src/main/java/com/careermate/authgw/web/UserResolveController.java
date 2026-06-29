package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.sms.PhoneSupport;
import com.careermate.authgw.sms.SmsProperties;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 内部「按手机号精确解析用户」接口，供下游服务（如 RAGForge）邀请成员时使用。
 *
 * <p>安全：仅通过 client_assertion 认证的可信 client 可调用（与 /oauth/introspect 一致），
 * 防止终端用户枚举手机号。仅做精确哈希匹配、不返回明文、不分页、不支持模糊搜索。
 */
@RestController
public class UserResolveController {

    private final ClientAuthenticator clientAuthenticator;
    private final AuthUserRepository authUserRepository;
    private final SmsProperties smsProperties;

    public UserResolveController(
            ClientAuthenticator clientAuthenticator,
            AuthUserRepository authUserRepository,
            SmsProperties smsProperties) {
        this.clientAuthenticator = clientAuthenticator;
        this.authUserRepository = authUserRepository;
        this.smsProperties = smsProperties;
    }

    @PostMapping(
            value = "/internal/users/resolve-by-phone",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> resolveByPhone(
            @RequestParam String phone,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        // 仅授权 client 可调用（防枚举）。
        clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);

        String normalized;
        try {
            normalized = PhoneSupport.requireMainlandPhone(phone);
        } catch (RuntimeException ex) {
            return Map.of("found", false, "registered", false, "reason", "INVALID_PHONE");
        }

        String hash = PhoneSupport.hashPhone(normalized, smsProperties.getPhoneHashPepper());
        String masked = PhoneSupport.maskPhone(normalized);
        return authUserRepository
                .findByPhoneHash(hash)
                .map(
                        u -> {
                            Map<String, Object> m = new LinkedHashMap<>();
                            m.put("found", true);
                            m.put("registered", true);
                            m.put("authUserId", u.id());
                            m.put("username", u.username());
                            m.put("maskedPhone", masked);
                            return m;
                        })
                .orElseGet(
                        () ->
                                Map.of(
                                        "found", false,
                                        "registered", false,
                                        "maskedPhone", masked));
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }
}
