package com.careermate.authgw.sms;

import com.aliyun.dypnsapi20170525.Client;
import com.aliyun.dypnsapi20170525.models.CheckSmsVerifyCodeRequest;
import com.aliyun.dypnsapi20170525.models.CheckSmsVerifyCodeResponse;
import com.aliyun.dypnsapi20170525.models.CheckSmsVerifyCodeResponseBody;
import com.aliyun.dypnsapi20170525.models.SendSmsVerifyCodeRequest;
import com.aliyun.dypnsapi20170525.models.SendSmsVerifyCodeResponse;
import com.aliyun.dypnsapi20170525.models.SendSmsVerifyCodeResponseBody;
import com.aliyun.tea.TeaException;
import com.aliyun.teaopenapi.models.Config;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.UUID;
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
            String outId = "authgw-" + UUID.randomUUID();
            String templateParam = objectMapper.writeValueAsString(Map.of(
                    "code", "##code##",
                    "min", Integer.toString(aliyun.getValidMinutes())));
            SendSmsVerifyCodeRequest sendRequest = new SendSmsVerifyCodeRequest()
                    .setPhoneNumber(request.phone())
                    .setOutId(outId)
                    .setSignName(aliyun.getSignName())
                    .setTemplateCode(aliyun.getTemplateCode())
                    .setTemplateParam(templateParam)
                    .setValidTime((long) CODE_VALID_SECONDS)
                    .setCodeLength((long) CODE_LENGTH)
                    .setCodeType(1L)
                    .setReturnVerifyCode(false);
            if (StringUtils.hasText(aliyun.getSchemeName())) {
                sendRequest.setSchemeName(aliyun.getSchemeName());
            }
            SendSmsVerifyCodeResponse response = createClient().sendSmsVerifyCode(sendRequest);
            return mapSendResult(response == null ? null : response.getBody(), request.phone(), outId);
        } catch (SmsException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Aliyun PNVS send exception, phone={}", PhoneSupport.maskPhone(request.phone()), ex);
            throw new SmsException(502, "SMS_PROVIDER_ERROR", "短信服务暂时不可用，请稍后再试");
        }
    }

    @Override
    public VerifyResult checkVerifyCode(VerifyRequest request) {
        ensureConfigured();
        try {
            CheckSmsVerifyCodeRequest checkRequest = new CheckSmsVerifyCodeRequest()
                    .setPhoneNumber(request.phone())
                    .setVerifyCode(request.verifyCode());
            SmsProperties.Aliyun aliyun = properties.getAliyun();
            if (StringUtils.hasText(request.outId())) {
                checkRequest.setOutId(request.outId());
            }
            if (StringUtils.hasText(aliyun.getSchemeName())) {
                checkRequest.setSchemeName(aliyun.getSchemeName());
            }
            CheckSmsVerifyCodeResponse response = createClient().checkSmsVerifyCode(checkRequest);
            return mapVerifyResult(response == null ? null : response.getBody(), request.phone(), resolveRequestId(response));
        } catch (SmsException ex) {
            throw ex;
        } catch (TeaException ex) {
            if (isVerificationFailed(ex)) {
                log.warn("Aliyun PNVS verify failed, code={}, phone={}",
                        ex.getCode(), PhoneSupport.maskPhone(request.phone()));
                return new VerifyResult(false, request.phone(), null, ex.getCode(), ex.getMessage(), "UNKNOWN");
            }
            log.error("Aliyun PNVS verify exception, code={}, phone={}",
                    ex.getCode(), PhoneSupport.maskPhone(request.phone()), ex);
            throw new SmsException(502, "SMS_PROVIDER_ERROR", "验证码暂时无法校验，请稍后再试");
        } catch (Exception ex) {
            log.error("Aliyun PNVS verify exception, phone={}", PhoneSupport.maskPhone(request.phone()), ex);
            throw new SmsException(502, "SMS_PROVIDER_ERROR", "验证码暂时无法校验，请稍后再试");
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

    private SendResult mapSendResult(SendSmsVerifyCodeResponseBody body, String phone, String fallbackOutId) {
        String responseCode = body == null ? null : body.getCode();
        String requestId = body == null ? null : body.getRequestId();
        String message = body == null ? null : body.getMessage();
        Boolean success = body == null ? null : body.getSuccess();
        String outId = body != null && body.getModel() != null ? body.getModel().getOutId() : null;
        if (!Boolean.TRUE.equals(success) || !"OK".equalsIgnoreCase(responseCode)) {
            log.error("Aliyun PNVS send failed, requestId={}, code={}, message={}, phone={}",
                    requestId, responseCode, message, PhoneSupport.maskPhone(phone));
            if (isRateLimited(responseCode, message)) {
                throw new SmsException(429, "SMS_PROVIDER_RATE_LIMITED", "验证码发送过于频繁，请稍后再试");
            }
            throw new SmsException(502, "SMS_PROVIDER_SEND_FAILED", "短信服务暂时不可用，请稍后再试");
        }
        String effectiveOutId = StringUtils.hasText(outId) ? outId : fallbackOutId;
        log.info("Aliyun PNVS send ok, requestId={}, hasOutId={}, phone={}",
                requestId, StringUtils.hasText(effectiveOutId), PhoneSupport.maskPhone(phone));
        return new SendResult(true, effectiveOutId, requestId, responseCode, message);
    }

    private boolean isRateLimited(String responseCode, String message) {
        String text = ((responseCode == null ? "" : responseCode) + " " + (message == null ? "" : message)).toLowerCase();
        return text.contains("limit")
                || text.contains("frequency")
                || text.contains("too many")
                || text.contains("频繁")
                || text.contains("限流")
                || text.contains("次数")
                || text.contains("business_limit_control");
    }

    private boolean isVerificationFailed(TeaException ex) {
        String text = ((ex.getCode() == null ? "" : ex.getCode()) + " "
                + (ex.getMessage() == null ? "" : ex.getMessage())).toLowerCase();
        return text.contains("验证失败")
                || text.contains("verification failed")
                || text.contains("verify failed");
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
