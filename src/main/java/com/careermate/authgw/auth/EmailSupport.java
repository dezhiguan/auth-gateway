package com.careermate.authgw.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Pattern;
import org.springframework.util.StringUtils;

/** 邮箱归一化与哈希。与 PhoneSupport 对应，保证全局唯一比较一致。 */
public final class EmailSupport {

    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private EmailSupport() {
    }

    /** trim + 小写，作为全局唯一比较的归一化形式。 */
    public static String normalizeEmail(String email) {
        if (email == null) {
            return null;
        }
        return email.trim().toLowerCase();
    }

    public static boolean isValidEmail(String email) {
        String normalized = normalizeEmail(email);
        return StringUtils.hasText(normalized) && EMAIL.matcher(normalized).matches();
    }

    public static String requireValidEmail(String email) {
        String normalized = normalizeEmail(email);
        if (!isValidEmail(normalized)) {
            throw new AuthException(400, "EMAIL_FORMAT_INVALID", "邮箱格式不正确");
        }
        return normalized;
    }

    public static String hashEmail(String email, String pepper) {
        return sha256Hex(normalizeEmail(email) + ":email:" + pepper);
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }
}
