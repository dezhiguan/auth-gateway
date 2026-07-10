package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.AuthUserRepository;
import com.careermate.authgw.oauth.ClientAuthenticator;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 内部接口（client 鉴权）：由 rag-forge 等可信应用调用，不对终端用户暴露。 */
@RestController
public class InternalUserController {

    private final ClientAuthenticator clientAuthenticator;
    private final AuthUserRepository userRepository;

    public InternalUserController(ClientAuthenticator clientAuthenticator, AuthUserRepository userRepository) {
        this.clientAuthenticator = clientAuthenticator;
        this.userRepository = userRepository;
    }

    /**
     * 递增用户 session_version，使该用户所有现存 access token 在下次使用时失效（最多 15 分钟）。
     * 场景：rag-forge 将成员移出组织后调用，确保被移出者 access token 因 session_version 不匹配而返回 403。
     */
    @PostMapping(value = "/internal/users/{userId}/invalidate-session", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> invalidateSession(
            @PathVariable long userId,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        userRepository.incrementSessionVersion(userId);
        return Map.of("invalidated", true, "userId", userId);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }
}
