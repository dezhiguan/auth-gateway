package com.careermate.authgw.sms;

public interface MobileSmsAuthProvider {

    SendResult sendVerifyCode(SendRequest request);

    VerifyResult checkVerifyCode(VerifyRequest request);

    record SendRequest(String phone, SmsScene scene, String code) {
    }

    record SendResult(
            boolean success,
            String outId,
            String providerRequestId,
            String providerCode,
            String providerMessage) {
    }

    record VerifyRequest(String phone, String verifyCode, String outId, SmsScene scene) {
    }

    record VerifyResult(
            boolean success,
            String phone,
            String providerRequestId,
            String providerCode,
            String providerMessage,
            String verifyResult) {
    }
}
