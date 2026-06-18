package com.careermate.authgw.sms;

import java.util.Locale;

public enum SmsScene {
    LOGIN("login"),
    REGISTER("register"),
    RESET("reset"),
    BIND_PHONE("bind_phone");

    private final String value;

    SmsScene(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static SmsScene fromValue(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if ("mobile_login".equals(normalized)) {
            return LOGIN;
        }
        if ("password_reset".equals(normalized)) {
            return RESET;
        }
        for (SmsScene scene : values()) {
            if (scene.value.equals(normalized)) {
                return scene;
            }
        }
        return null;
    }
}
