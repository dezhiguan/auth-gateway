package com.careermate.authgw.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class JwtSigner {

    private final JwksProvider jwksProvider;

    public JwtSigner(JwksProvider jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    public String sign(Map<String, Object> claims) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        claims.forEach(claimsBuilder::claim);

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(jwksProvider.activeKey().getKeyID())
                        .type(com.nimbusds.jose.JOSEObjectType.JWT)
                        .build(),
                claimsBuilder.build());
        try {
            jwt.sign(new RSASSASigner(jwksProvider.activeKey()));
            return jwt.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Failed to sign JWT", ex);
        }
    }
}
