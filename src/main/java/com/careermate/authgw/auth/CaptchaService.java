package com.careermate.authgw.auth;

import com.careermate.authgw.sms.SmsCodeStore;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.springframework.stereotype.Service;

/**
 * 图形验证码：登录失败次数过多后要求完成，替代粗暴的时间锁——输对即放行。
 * 验证码答案按 challengeId 存入短期存储（一次性、可过期），图片以 PNG data URL 返回给前端展示。
 */
@Service
public class CaptchaService {

    private static final Duration TTL = Duration.ofMinutes(5);
    // 去掉易混字符 0/O/1/I/L，降低人工识别错误率。
    private static final char[] CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789".toCharArray();
    private static final int LENGTH = 4;

    private final SmsCodeStore store;
    private final SecureRandom random = new SecureRandom();

    public CaptchaService(SmsCodeStore store) {
        this.store = store;
    }

    /** 生成一张新验证码：返回 challengeId 与图片 data URL，答案已入库（TTL 内有效、一次性）。 */
    public Captcha generate() {
        String code = randomCode();
        String challengeId = UUID.randomUUID().toString();
        store.setValue(storeKey(challengeId), code, TTL);
        return new Captcha(challengeId, renderDataUrl(code));
    }

    /** 一次性校验：命中即消费；大小写不敏感；challengeId/答案为空、不存在、已过期、已用过均视为失败。 */
    public boolean verify(String challengeId, String answer) {
        if (challengeId == null || challengeId.isBlank() || answer == null || answer.isBlank()) {
            return false;
        }
        Optional<String> expected = store.getValue(storeKey(challengeId));
        if (expected.isEmpty()) {
            return false;
        }
        store.delete(storeKey(challengeId));
        return expected.get().equalsIgnoreCase(answer.trim());
    }

    private String randomCode() {
        StringBuilder sb = new StringBuilder(LENGTH);
        for (int i = 0; i < LENGTH; i++) {
            sb.append(CHARS[random.nextInt(CHARS.length)]);
        }
        return sb.toString();
    }

    private String renderDataUrl(String code) {
        int w = 120;
        int h = 44;
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(new Color(245, 246, 250));
        g.fillRect(0, 0, w, h);
        for (int i = 0; i < 6; i++) {
            g.setColor(new Color(random.nextInt(180) + 40, random.nextInt(180) + 40, random.nextInt(180) + 40));
            g.drawLine(random.nextInt(w), random.nextInt(h), random.nextInt(w), random.nextInt(h));
        }
        for (int i = 0; i < 40; i++) {
            g.setColor(new Color(random.nextInt(200), random.nextInt(200), random.nextInt(200)));
            g.fillRect(random.nextInt(w), random.nextInt(h), 1, 1);
        }
        for (int i = 0; i < code.length(); i++) {
            g.setColor(new Color(30 + random.nextInt(80), 30 + random.nextInt(80), 90 + random.nextInt(90)));
            g.setFont(new Font("SansSerif", Font.BOLD, 28 + random.nextInt(4)));
            double angle = (random.nextDouble() - 0.5) * 0.5;
            int x = 12 + i * 26;
            int y = 32;
            g.rotate(angle, x, y);
            g.drawString(String.valueOf(code.charAt(i)), x, y);
            g.rotate(-angle, x, y);
        }
        g.dispose();
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(img, "png", baos);
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            throw new IllegalStateException("failed to render captcha image", e);
        }
    }

    private String storeKey(String challengeId) {
        return "authgw:captcha:" + challengeId;
    }

    public record Captcha(String challengeId, String image) {}
}
