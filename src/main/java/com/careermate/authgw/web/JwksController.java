package com.careermate.authgw.web;

import com.careermate.authgw.crypto.JwksProvider;
import java.util.concurrent.TimeUnit;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {

    private final JwksProvider jwksProvider;

    public JwksController(JwksProvider jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(1, TimeUnit.HOURS).cachePublic())
                .contentType(MediaType.APPLICATION_JSON)
                .body(jwksProvider.publicJwksJson());
    }
}
