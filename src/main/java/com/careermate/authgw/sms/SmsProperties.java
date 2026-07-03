package com.careermate.authgw.sms;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.sms")
public class SmsProperties {

    private String storage = "memory";
    private String phoneHashPepper = "auth-gateway-dev-pepper";
    private int codeTtlSeconds = 300;
    private String mockCode = "123456";

    // 发送侧限流（防短信轰炸）：默认值已收紧，可经 auth.sms.* / 环境变量覆盖，无需重发版调优。
    private int phoneDaySendLimit = 5; // 同一手机号每天最多发送条数
    private int ipMinuteSendLimit = 10; // 同一 IP 每分钟最多发送条数
    private int ipDaySendLimit = 100; // 同一 IP 每天最多发送条数（原缺失，补齐）
    private int sendCooldownSeconds = 60; // 同一手机号两次发送的最小间隔

    private Aliyun aliyun = new Aliyun();

    public String getStorage() {
        return storage;
    }

    public void setStorage(String storage) {
        this.storage = storage;
    }

    public String getPhoneHashPepper() {
        return phoneHashPepper;
    }

    public void setPhoneHashPepper(String phoneHashPepper) {
        this.phoneHashPepper = phoneHashPepper;
    }

    public int getCodeTtlSeconds() {
        return codeTtlSeconds;
    }

    public void setCodeTtlSeconds(int codeTtlSeconds) {
        this.codeTtlSeconds = codeTtlSeconds;
    }

    public String getMockCode() {
        return mockCode;
    }

    public void setMockCode(String mockCode) {
        this.mockCode = mockCode;
    }

    public int getPhoneDaySendLimit() {
        return phoneDaySendLimit;
    }

    public void setPhoneDaySendLimit(int phoneDaySendLimit) {
        this.phoneDaySendLimit = phoneDaySendLimit;
    }

    public int getIpMinuteSendLimit() {
        return ipMinuteSendLimit;
    }

    public void setIpMinuteSendLimit(int ipMinuteSendLimit) {
        this.ipMinuteSendLimit = ipMinuteSendLimit;
    }

    public int getIpDaySendLimit() {
        return ipDaySendLimit;
    }

    public void setIpDaySendLimit(int ipDaySendLimit) {
        this.ipDaySendLimit = ipDaySendLimit;
    }

    public int getSendCooldownSeconds() {
        return sendCooldownSeconds;
    }

    public void setSendCooldownSeconds(int sendCooldownSeconds) {
        this.sendCooldownSeconds = sendCooldownSeconds;
    }

    public Aliyun getAliyun() {
        return aliyun;
    }

    public void setAliyun(Aliyun aliyun) {
        this.aliyun = aliyun;
    }

    public static class Aliyun {
        private String accessKeyId = "";
        private String accessKeySecret = "";
        private String signName = "";
        private String templateCode = "";
        private int validMinutes = 5;
        private String endpoint = "dypnsapi.aliyuncs.com";
        private String region = "cn-hangzhou";
        private String schemeName = "";

        public String getAccessKeyId() {
            return accessKeyId;
        }

        public void setAccessKeyId(String accessKeyId) {
            this.accessKeyId = accessKeyId;
        }

        public String getAccessKeySecret() {
            return accessKeySecret;
        }

        public void setAccessKeySecret(String accessKeySecret) {
            this.accessKeySecret = accessKeySecret;
        }

        public String getSignName() {
            return signName;
        }

        public void setSignName(String signName) {
            this.signName = signName;
        }

        public String getTemplateCode() {
            return templateCode;
        }

        public void setTemplateCode(String templateCode) {
            this.templateCode = templateCode;
        }

        public int getValidMinutes() {
            return validMinutes;
        }

        public void setValidMinutes(int validMinutes) {
            this.validMinutes = validMinutes;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public String getRegion() {
            return region;
        }

        public void setRegion(String region) {
            this.region = region;
        }

        public String getSchemeName() {
            return schemeName;
        }

        public void setSchemeName(String schemeName) {
            this.schemeName = schemeName;
        }
    }
}
