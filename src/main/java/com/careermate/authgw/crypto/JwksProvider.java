package com.careermate.authgw.crypto;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class JwksProvider {

    private final RSAKey activeKey;
    private final RSAKey previousKey;
    private final JWKSet publicJwkSet;

    public JwksProvider(JwksProperties properties) {
        this.activeKey = loadRsaKey(properties.getActiveKid(), properties.getKeyStore().getActivePrivateKey());
        this.previousKey = loadOptionalRsaKey(properties.getPreviousKid(), properties.getKeyStore().getPreviousPrivateKey());

        List<JWK> publicKeys = new ArrayList<>();
        publicKeys.add(activeKey.toPublicJWK());
        if (previousKey != null) {
            publicKeys.add(previousKey.toPublicJWK());
        }
        this.publicJwkSet = new JWKSet(publicKeys);
    }

    public RSAKey activeKey() {
        return activeKey;
    }

    public String publicJwksJson() {
        return publicJwkSet.toString();
    }

    private RSAKey loadOptionalRsaKey(String kid, String pemPath) {
        if (!StringUtils.hasText(kid) || !StringUtils.hasText(pemPath)) {
            return null;
        }
        return loadRsaKey(kid, pemPath);
    }

    private RSAKey loadRsaKey(String kid, String pemPath) {
        if (!StringUtils.hasText(kid)) {
            throw new IllegalStateException("jwks kid must be configured");
        }
        if (!StringUtils.hasText(pemPath)) {
            throw new IllegalStateException("jwks private key path must be configured");
        }

        try {
            RSAPrivateKey privateKey = readPkcs8PrivateKey(Path.of(pemPath));
            RSAPublicKey publicKey = derivePublicKey(privateKey);
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .build();
        } catch (IOException | GeneralSecurityException ex) {
            throw new IllegalStateException("Failed to load RSA private key from " + pemPath, ex);
        }
    }

    private RSAPrivateKey readPkcs8PrivateKey(Path path) throws IOException, GeneralSecurityException {
        String pem = Files.readString(path, StandardCharsets.US_ASCII);
        String normalized = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(normalized);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(der);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private RSAPublicKey derivePublicKey(RSAPrivateKey privateKey) throws GeneralSecurityException {
        if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
            throw new GeneralSecurityException("RSA private key must include CRT parameters");
        }
        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent()));
    }
}
