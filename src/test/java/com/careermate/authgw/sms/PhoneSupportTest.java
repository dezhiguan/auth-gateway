package com.careermate.authgw.sms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PhoneSupportTest {

    @Test
    void normalizesMainlandPhoneVariants() {
        assertThat(PhoneSupport.normalizePhone(" +86 138-0000-0000 ")).isEqualTo("13800000000");
        assertThat(PhoneSupport.normalizePhone("8613800000000")).isEqualTo("13800000000");
        assertThat(PhoneSupport.requireMainlandPhone("13800000000")).isEqualTo("13800000000");
    }

    @Test
    void rejectsInvalidMainlandPhone() {
        assertThatThrownBy(() -> PhoneSupport.requireMainlandPhone("12800000000"))
                .isInstanceOfSatisfying(SmsException.class, ex -> {
                    assertThat(ex.status()).isEqualTo(400);
                    assertThat(ex.code()).isEqualTo("PHONE_FORMAT_INVALID");
                });
    }

    @Test
    void masksPhoneAndFallsBackForInvalidInput() {
        assertThat(PhoneSupport.maskPhone("+8613800000000")).isEqualTo("138****0000");
        assertThat(PhoneSupport.maskPhone("bad")).isEqualTo("****");
        assertThat(PhoneSupport.maskPhone(null)).isEqualTo("****");
    }

    @Test
    void hashesAreStableAndPepperSensitive() {
        String phoneHash = PhoneSupport.hashPhone("+8613800000000", "pepper");
        assertThat(phoneHash).isEqualTo(PhoneSupport.hashPhone("13800000000", "pepper"));
        assertThat(phoneHash).isNotEqualTo(PhoneSupport.hashPhone("13800000000", "other"));
        assertThat(PhoneSupport.hashIp(" 1.1.1.1, 2.2.2.2 ", "pepper"))
                .isEqualTo(PhoneSupport.hashIp("1.1.1.1", "pepper"));
        assertThat(PhoneSupport.hashCode("123456", "pepper")).hasSize(64);
    }

    @Test
    void generatesNumericCodeWithRequestedLength() {
        assertThat(PhoneSupport.generateNumericCode(6)).matches("\\d{6}");
        assertThat(PhoneSupport.generateNumericCode(0)).isEmpty();
    }

    @Test
    void normalizesIp() {
        assertThat(PhoneSupport.normalizeIp(null)).isEqualTo("unknown");
        assertThat(PhoneSupport.normalizeIp(" ")).isEqualTo("unknown");
        assertThat(PhoneSupport.normalizeIp(" 10.0.0.1, 10.0.0.2 ")).isEqualTo("10.0.0.1");
    }
}
