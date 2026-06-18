package com.careermate.authgw.sms;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.regex.Pattern;
import org.springframework.util.StringUtils;

public final class PhoneSupport {

    private static final Pattern MAINLAND_PHONE = Pattern.compile("^1[3-9]\\d{9}$");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PhoneSupport() {
    }

    public static String normalizePhone(String phone) {
        if (phone == null) {
            return null;
        }
        String normalized = phone.trim().replace(" ", "").replace("-", "");
        if (normalized.startsWith("+86")) {
            return normalized.substring(3);
        }
        if (normalized.startsWith("86") && normalized.length() == 13) {
            return normalized.substring(2);
        }
        return normalized;
    }

    public static boolean isMainlandPhone(String phone) {
        return StringUtils.hasText(phone) && MAINLAND_PHONE.matcher(phone).matches();
    }

    public static String requireMainlandPhone(String phone) {
        String normalized = normalizePhone(phone);
        if (!isMainlandPhone(normalized)) {
            throw new SmsException(400, "PHONE_FORMAT_INVALID", "phone must be a valid mainland China mobile number");
        }
        return normalized;
    }

    public static String maskPhone(String phone) {
        String normalized = normalizePhone(phone);
        if (!StringUtils.hasText(normalized) || normalized.length() != 11) {
            return "****";
        }
        return normalized.substring(0, 3) + "****" + normalized.substring(7);
    }

    public static String hashPhone(String phone, String pepper) {
        return sha256Hex(normalizePhone(phone) + ":" + pepper);
    }

    public static String hashIp(String ip, String pepper) {
        return sha256Hex(normalizeIp(ip) + ":ip:" + pepper);
    }

    public static String hashCode(String code, String pepper) {
        return sha256Hex(code + ":code:" + pepper);
    }

    public static String generateNumericCode(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(SECURE_RANDOM.nextInt(10));
        }
        return builder.toString();
    }

    public static String normalizeIp(String ip) {
        if (!StringUtils.hasText(ip)) {
            return "unknown";
        }
        int commaIndex = ip.indexOf(',');
        if (commaIndex > 0) {
            return ip.substring(0, commaIndex).trim();
        }
        return ip.trim();
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
