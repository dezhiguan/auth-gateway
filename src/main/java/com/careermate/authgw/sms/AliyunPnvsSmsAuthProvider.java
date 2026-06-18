package com.careermate.authgw.sms;

import com.aliyun.dypnsapi20170525.Client;
import com.aliyun.dypnsapi20170525.models.CheckSmsVerifyCodeRequest;
import com.aliyun.dypnsapi20170525.models.CheckSmsVerifyCodeResponse;
import com.aliyun.dypnsapi20170525.models.CheckSmsVerifyCodeResponseBody;
import com.aliyun.dypnsapi20170525.models.SendSmsVerifyCodeRequest;
import com.aliyun.dypnsapi20170525.models.SendSmsVerifyCodeResponse;
import com.aliyun.dypnsapi20170525.models.SendSmsVerifyCodeResponseBody;
import com.aliyun.teaopenapi.models.Config;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@Profile("prod")
public class AliyunPnvsSmsAuthProvider implements MobileSmsAuthProvider {

    private static final Logger log = LoggerFactory.getLogger(AliyunPnvsSmsAuthProvider.class);
    private static final int CODE_VALID_SECONDS = 300;
    private static final int CODE_LENGTH = 6;
    private static final String VERIFY_PASS = "PASS";

    private final SmsProperties properties;
    private final ObjectMapper objectMapper;

    public AliyunPnvsSmsAuthProvider(SmsProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    public SendResult sendVerifyCode(SendRequest request) {
        ensureConfigured();
        try {
            SmsProperties.Aliyun aliyun = properties.getAliyun();
            String templateParam = objectMapper.writeValueAsString(Map.of(
                    "code", "##code##",
                    "min", Integer.toString(aliyun.getValidMinutes())));
            SendSmsVerifyCodeRequest sendRequest = new SendSmsVerifyCodeRequest()
                    .setPhoneNumber(request.phone())
                    .setSignName(aliyun.getSignName())
                    .setTemplateCode(aliyun.getTemplateCode())
                    .setTemplateParam(templateParam)
                    .setValidTime((long) CODE_VALID_SECONDS)
                    .setCodeLength((long) CODE_LENGTH)
                    .setCodeType(1L)
                    .setReturnVerifyCode(false);
            SendSmsVerifyCodeResponse response = createClient().sendSmsVerifyCode(sendRequest);
            return mapSendResult(response == null ? null : response.getBody(), request.phone());
        } catch (SmsException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Aliyun PNVS send exception, phone={}", PhoneSupport.maskPhone(request.phone()), ex);
            throw new SmsException(502, "SMS_PROVIDER_ERROR", "sms provider send failed");
        }
    }

    @Override
    public VerifyResult checkVerifyCode(VerifyRequest request) {
        ensureConfigured();
        try {
            CheckSmsVerifyCodeRequest checkRequest = new CheckSmsVerifyCodeRequest()
                    .setPhoneNumber(request.phone())
                    .setVerifyCode(request.verifyCode());
            if (StringUtils.hasText(request.outId())) {
                checkRequest.setOutId(request.outId());
            }
            CheckSmsVerifyCodeResponse response = createClient().checkSmsVerifyCode(checkRequest);
            return mapVerifyResult(response == null ? null : response.getBody(), request.phone(), resolveRequestId(response));
        } catch (SmsException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Aliyun PNVS verify exception, phone={}", PhoneSupport.maskPhone(request.phone()), ex);
            throw new SmsException(502, "SMS_PROVIDER_ERROR", "sms provider verify failed");
        }
    }

    private void ensureConfigured() {
        SmsProperties.Aliyun aliyun = properties.getAliyun();
        if (!StringUtils.hasText(aliyun.getAccessKeyId())
                || !StringUtils.hasText(aliyun.getAccessKeySecret())
                || !StringUtils.hasText(aliyun.getSignName())
                || !StringUtils.hasText(aliyun.getTemplateCode())) {
            throw new SmsException(500, "ALIYUN_SMS_CONFIG_INCOMPLETE", "Aliyun SMS configuration is incomplete");
        }
    }

    private SendResult mapSendResult(SendSmsVerifyCodeResponseBody body, String phone) {
        String responseCode = body == null ? null : body.getCode();
        String requestId = body == null ? null : body.getRequestId();
        String message = body == null ? null : body.getMessage();
        Boolean success = body == null ? null : body.getSuccess();
        String outId = body != null && body.getModel() != null ? body.getModel().getOutId() : null;
        if (!Boolean.TRUE.equals(success) || !"OK".equalsIgnoreCase(responseCode)) {
            log.error("Aliyun PNVS send failed, requestId={}, code={}, message={}, phone={}",
                    requestId, responseCode, message, PhoneSupport.maskPhone(phone));
            throw new SmsException(502, "SMS_PROVIDER_SEND_FAILED", "sms provider send failed");
        }
        return new SendResult(true, outId, requestId, responseCode, message);
    }

    private VerifyResult mapVerifyResult(CheckSmsVerifyCodeResponseBody body, String phone, String requestId) {
        String responseCode = body == null ? null : body.getCode();
        String message = body == null ? null : body.getMessage();
        Boolean success = body == null ? null : body.getSuccess();
        String verifyResult = body != null && body.getModel() != null ? body.getModel().getVerifyResult() : null;
        boolean passed = Boolean.TRUE.equals(success)
                && "OK".equalsIgnoreCase(responseCode)
                && VERIFY_PASS.equalsIgnoreCase(verifyResult);
        return new VerifyResult(passed, phone, requestId, responseCode, message, verifyResult);
    }

    private String resolveRequestId(CheckSmsVerifyCodeResponse response) {
        if (response == null || response.getHeaders() == null) {
            return null;
        }
        return response.getHeaders().get("x-acs-request-id");
    }

    private Client createClient() throws Exception {
        SmsProperties.Aliyun aliyun = properties.getAliyun();
        Config config = new Config()
                .setAccessKeyId(aliyun.getAccessKeyId())
                .setAccessKeySecret(aliyun.getAccessKeySecret())
                .setEndpoint(aliyun.getEndpoint())
                .setRegionId(aliyun.getRegion());
        return new Client(config);
    }
}
