package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.TokenService;
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
    private final TokenService tokenService;

    public InternalUserController(ClientAuthenticator clientAuthenticator, TokenService tokenService) {
        this.clientAuthenticator = clientAuthenticator;
        this.tokenService = tokenService;
    }

    /**
     * 失效用户的全部会话：递增 session_version、吊销 refresh_tokens，并发布 session.revoked 事件。
     * 场景：rag-forge 将成员移出组织后调用，被移出者旧 access token 经事件被下游标记撤销、refresh token 失效，
     * 从而在下次访问/续期时被踢下线（复用与全端退出/改密一致的会话撤销链，不再依赖跨库查 session_version）。
     */
    @PostMapping(value = "/internal/users/{userId}/invalidate-session", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> invalidateSession(
            @PathVariable long userId,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        tokenService.revokeUserSessions(userId, "org-member-removed");
        return Map.of("invalidated", true, "userId", userId);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }
}
