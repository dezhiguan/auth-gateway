package com.careermate.authgw.auth;

public class AuthException extends RuntimeException {

    private final int status;
    private final String code;
    // 仅 CAPTCHA_REQUIRED 场景携带：图形验证码图片（data URL）与本次挑战 id，供前端展示与回填。
    private final String captchaImage;
    private final String challengeId;

    public AuthException(int status, String code, String message) {
        this(status, code, message, null, null);
    }

    public AuthException(int status, String code, String message, String captchaImage, String challengeId) {
        super(message);
        this.status = status;
        this.code = code;
        this.captchaImage = captchaImage;
        this.challengeId = challengeId;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public String captchaImage() {
        return captchaImage;
    }

    public String challengeId() {
        return challengeId;
    }
}
