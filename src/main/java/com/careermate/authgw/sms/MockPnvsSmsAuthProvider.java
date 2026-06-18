package com.careermate.authgw.sms;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!prod")
public class MockPnvsSmsAuthProvider implements MobileSmsAuthProvider {

    private static final Logger log = LoggerFactory.getLogger(MockPnvsSmsAuthProvider.class);

    private final SmsProperties properties;

    public MockPnvsSmsAuthProvider(SmsProperties properties) {
        this.properties = properties;
    }

    @Override
    public SendResult sendVerifyCode(SendRequest request) {
        log.info("Mock SMS send, phone={}, scene={}", PhoneSupport.maskPhone(request.phone()), request.scene().value());
        return new SendResult(true, "mock-" + UUID.randomUUID(), "mock-send", "OK", "mock sent");
    }

    @Override
    public VerifyResult checkVerifyCode(VerifyRequest request) {
        boolean passed = properties.getMockCode().equals(request.verifyCode());
        return new VerifyResult(
                passed,
                request.phone(),
                "mock-verify",
                "OK",
                passed ? "mock verified" : "mock rejected",
                passed ? "PASS" : "FAIL");
    }
}
