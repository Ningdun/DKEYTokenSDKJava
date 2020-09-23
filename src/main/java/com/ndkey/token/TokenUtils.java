package com.ndkey.token;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TokenUtils {

    /**
     * 生成动态密码
     *
     * @param key 令牌的种子,相当于secret解码后的数据
     * @param timeInMillis Unix时间戳，单位：毫秒
     * @param period 动态密码的变化周期30 或 60 秒
     * @param digits 动态密码的长度
     * @return
     */
    public static String generateTOTP(byte[] key, long timeInMillis, int period, int digits) {
        return generateTOTP(key, timeInMillis, period, digits, "HmacSHA1");
    }

    /**
     * 验证动态密码
     *
     * @param key 令牌的种子,相当于secret解码后的数据
     * @param timeInMillis Unix时间戳，单位：毫秒
     * @param period 动态密码的变化周期30 或 60 秒
     * @param digits 动态密码的长度
     * @param otp 动态密码
     * @param window
     * 窗口大小。值为0：用timeInMillis生成1个密码做认证。值为1：用timeInMillis、向前1个时间周期、向后1个时间周期生成3个密码做认证。以此类推。。
     * @return
     */
    public static boolean verifyTOTP(byte[] key, long timeInMillis, int period, int digits, String otp, int window) {
        return verifyTOTP(key, timeInMillis, period, digits, "HmacSHA1", otp, window);
    }

    private static boolean verifyTOTP(byte[] key, long timeInMillis, int period, int digits, String algorithm, String otp, int window) {
        long[] times = new long[1 + window * 2];
        times[0] = timeInMillis;
        long o = 0;
        for (int i = 1; i < times.length; i = i + 2) {
            o = o + period * 1000;
            times[i] = timeInMillis - o;
            times[i + 1] = timeInMillis + o;
        }
        boolean success = false;
        for (long time : times) {
            if (generateTOTP(key, time, period, digits, algorithm).equals(otp)) {
                success = true;
                break;
            }
        }
        return success;
    }

    private static String generateTOTP(byte[] key, long timeInMillis, int period, int digits, String algorithm) {
        long T = timeInMillis / 1000 / period;
        byte[] msg = new byte[8];
        for (int i = msg.length - 1; i >= 0; i--) {
            msg[i] = (byte) (T & 0xff);
            T >>= 8;
        }
        byte[] hash = hmac_sha(algorithm, key, msg);
        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        int otp = binary % DIGITS_POWER[digits];
        String result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }

    private static final int[] DIGITS_POWER // 0 1  2   3    4     5      6       7        8        9
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};

    private static byte[] hmac_sha(String algorithm, byte[] key, byte[] text) {
        try {
            Mac hmac = Mac.getInstance(algorithm);
            SecretKeySpec macKey = new SecretKeySpec(key, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

}
