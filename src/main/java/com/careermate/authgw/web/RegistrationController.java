package com.careermate.authgw.web;

import com.careermate.authgw.auth.AuthException;
import com.careermate.authgw.auth.RegistrationService;
import com.careermate.authgw.sms.SmsException;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 注册 / 账号补全入口。公开接口（仅创建/补全账号，不签发 token；前端随后正常登录）。
 */
@RestController
public class RegistrationController {

    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping(value = "/auth/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public RegisterResponse register(@RequestBody RegisterRequest request) {
        RegistrationService.RegisterResult result = registrationService.register(
                request.phone(),
                request.smsCode(),
                request.username(),
                request.email(),
                request.password(),
                request.app());
        String message = result.linked()
                ? "该手机号已注册，已为你关联并补全账号信息"
                : "注册成功";
        return new RegisterResponse(result.userId(), result.linked(), message);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    @ExceptionHandler(SmsException.class)
    public ResponseEntity<Map<String, Object>> handleSmsException(SmsException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "message", ex.getMessage()));
    }

    public record RegisterRequest(
            String phone,
            String smsCode,
            String username,
            String email,
            String password,
            String app) {
    }

    public record RegisterResponse(long userId, boolean linked, String message) {
    }
}
