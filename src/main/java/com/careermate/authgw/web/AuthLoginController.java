package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.CaptchaService;
import com.careermate.authgw.auth.LoginService;
import com.careermate.authgw.auth.OAuthClient;
import com.careermate.authgw.auth.TokenPair;
import com.careermate.authgw.oauth.ClientAuthenticator;
import com.careermate.authgw.sms.SmsException;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthLoginController {

    private final ClientAuthenticator clientAuthenticator;
    private final LoginService loginService;

    public AuthLoginController(ClientAuthenticator clientAuthenticator, LoginService loginService) {
        this.clientAuthenticator = clientAuthenticator;
        this.loginService = loginService;
    }

    /** 换一张：前端"看不清/刷新"时获取一张新的图形验证码。 */
    @GetMapping("/auth/captcha")
    public ResponseEntity<Map<String, Object>> captcha() {
        CaptchaService.Captcha captcha = loginService.newCaptcha();
        Map<String, Object> body = new HashMap<>();
        body.put("captchaImage", captcha.image());
        body.put("challengeId", captcha.challengeId());
        return ResponseEntity.ok(body);
    }

    @PostMapping(value = "/auth/login/password", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public LoginResponse loginPassword(
            @RequestParam String account,
            @RequestParam String password,
            @RequestParam(name = "captcha", required = false) String captcha,
            @RequestParam(name = "challenge_id", required = false) String challengeId,
            @RequestParam("target_aud") String targetAud,
            @RequestParam(name = "remember", required = false, defaultValue = "false") boolean remember,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        OAuthClient client = clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        LoginService.LoginResult result =
                loginService.loginPassword(account, password, captcha, challengeId, targetAud, client, remember);
        TokenPair tokens = result.tokens();
        return new LoginResponse(
                tokens.accessToken(), tokens.refreshToken(), tokens.tokenType(), tokens.expiresIn(),
                tokens.refreshExpiresIn(), result.termsUpdateRequired(), result.pendingDeletion());
    }

    @PostMapping(value = "/auth/login/mobile", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public LoginResponse loginMobile(
            @RequestParam String phone,
            @RequestParam String code,
            @RequestParam("target_aud") String targetAud,
            @RequestParam(name = "remember", required = false, defaultValue = "false") boolean remember,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        OAuthClient client = clientAuthenticator.authenticate(clientId, clientAssertionType, clientAssertion);
        LoginService.LoginResult result = loginService.loginMobile(phone, code, targetAud, client, remember);
        TokenPair tokens = result.tokens();
        return new LoginResponse(
                tokens.accessToken(), tokens.refreshToken(), tokens.tokenType(), tokens.expiresIn(),
                tokens.refreshExpiresIn(), result.termsUpdateRequired(), result.pendingDeletion());
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        if (ex.status() == 423) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", ex.code());
            body.put("message", ex.getMessage());
            // ACCOUNT_PENDING_DELETION 不附带验证码字段
            if (!"ACCOUNT_PENDING_DELETION".equals(ex.code())) {
                body.put("captcha_required", true);
                if (ex.captchaImage() != null) {
                    body.put("captchaImage", ex.captchaImage());
                }
                if (ex.challengeId() != null) {
                    body.put("challengeId", ex.challengeId());
                }
            }
            return ResponseEntity.status(ex.status()).body(body);
        }
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    @ExceptionHandler(SmsException.class)
    public ResponseEntity<Map<String, Object>> handleSmsException(SmsException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    @JsonPropertyOrder({"access_token", "refresh_token", "token_type", "expires_in", "refresh_expires_in", "terms_update_required", "pending_deletion"})
    public record LoginResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn,
            @JsonProperty("refresh_expires_in") long refreshExpiresIn,
            @JsonProperty("terms_update_required") boolean termsUpdateRequired,
            @JsonProperty("pending_deletion") boolean pendingDeletion) {
    }
}
