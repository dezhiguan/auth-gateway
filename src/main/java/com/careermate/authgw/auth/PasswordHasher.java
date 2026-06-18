package com.careermate.authgw.auth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordHasher {

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

    public boolean matches(String rawPassword, String passwordHash) {
        return passwordEncoder.matches(rawPassword, passwordHash);
    }

    public String hash(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }
}
