package com.careermate.authgw.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JwksProviderAndJwtSignerTest {

    @TempDir Path tempDir;

    @Test
    void providerRequiresKidAndPrivateKeyPath() {
        JwksProperties missingKid = new JwksProperties();
        missingKid.getKeyStore().setActivePrivateKey("missing.pem");
        assertThatThrownBy(() -> new JwksProvider(missingKid))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("kid");

        JwksProperties missingKeyPath = new JwksProperties();
        missingKeyPath.setActiveKid("active");
        assertThatThrownBy(() -> new JwksProvider(missingKeyPath))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("private key path");
    }

    @Test
    void publicJwksExposeActiveAndPreviousPublicKeysOnly() throws Exception {
        Path active = writePkcs8("active.pem", new RSAKeyGenerator(2048).keyID("active").generate());
        Path previous = writePkcs8("previous.pem", new RSAKeyGenerator(2048).keyID("previous").generate());
        JwksProvider provider = new JwksProvider(properties(active, previous));

        JWKSet publicSet = JWKSet.parse(provider.publicJwksJson());

        assertThat(publicSet.getKeys()).hasSize(2);
        assertThat(publicSet.getKeyByKeyId("active").toRSAKey().isPrivate()).isFalse();
        assertThat(publicSet.getKeyByKeyId("previous").toRSAKey().isPrivate()).isFalse();
        assertThat(provider.activeKey().getKeyID()).isEqualTo("active");
    }

    @Test
    void jwtSignerSignsWithActiveKidAndClaims() throws Exception {
        Path active = writePkcs8("active.pem", new RSAKeyGenerator(2048).keyID("active").generate());
        JwksProvider provider = new JwksProvider(properties(active, null));
        JwtSigner signer = new JwtSigner(provider);

        String token = signer.sign(Map.of("sub", "user:12", "scope", "rag:search"));
        SignedJWT jwt = SignedJWT.parse(token);
        JWSHeader header = jwt.getHeader();

        assertThat(header.getKeyID()).isEqualTo("active");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("sub")).isEqualTo("user:12");
        assertThat(jwt.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(provider.activeKey().toPublicJWK()))).isTrue();
    }

    @Test
    void jwtSignerSignsJwtClaimsSet() throws Exception {
        Path active = writePkcs8("active.pem", new RSAKeyGenerator(2048).keyID("active").generate());
        JwtSigner signer = new JwtSigner(new JwksProvider(properties(active, null)));

        String token = signer.sign(new JWTClaimsSet.Builder().subject("user:99").issuer("issuer").build());

        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getSubject()).isEqualTo("user:99");
    }

    private JwksProperties properties(Path activePrivateKey, Path previousPrivateKey) {
        JwksProperties properties = new JwksProperties();
        properties.setActiveKid("active");
        properties.getKeyStore().setActivePrivateKey(activePrivateKey.toString());
        if (previousPrivateKey != null) {
            properties.setPreviousKid("previous");
            properties.getKeyStore().setPreviousPrivateKey(previousPrivateKey.toString());
        }
        return properties;
    }

    private Path writePkcs8(String filename, RSAKey key) throws Exception {
        Path path = tempDir.resolve(filename);
        byte[] encoded = key.toRSAPrivateKey().getEncoded();
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        Files.writeString(path, "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----\n");
        return path;
    }
}
