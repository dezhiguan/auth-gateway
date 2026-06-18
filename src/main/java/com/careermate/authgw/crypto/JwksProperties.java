package com.careermate.authgw.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwks")
public class JwksProperties {

    private String activeKid;
    private String previousKid;
    private KeyStore keyStore = new KeyStore();

    public String getActiveKid() {
        return activeKid;
    }

    public void setActiveKid(String activeKid) {
        this.activeKid = activeKid;
    }

    public String getPreviousKid() {
        return previousKid;
    }

    public void setPreviousKid(String previousKid) {
        this.previousKid = previousKid;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public static class KeyStore {
        private String activePrivateKey;
        private String previousPrivateKey;

        public String getActivePrivateKey() {
            return activePrivateKey;
        }

        public void setActivePrivateKey(String activePrivateKey) {
            this.activePrivateKey = activePrivateKey;
        }

        public String getPreviousPrivateKey() {
            return previousPrivateKey;
        }

        public void setPreviousPrivateKey(String previousPrivateKey) {
            this.previousPrivateKey = previousPrivateKey;
        }
    }
}
