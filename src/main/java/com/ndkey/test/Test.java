package com.ndkey.test;

import com.ndkey.token.TokenUtils;
import java.util.Calendar;
import org.apache.commons.codec.binary.Base32;

public class Test {

    public static void main(String[] args) {
        try {
            byte[] key = new Base32().decode("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ");
            long timeInMillis = Calendar.getInstance().getTimeInMillis();
            int period = 30;
            int digits = 6;
            int window = 0;

            String otp = TokenUtils.generateTOTP(key, timeInMillis, period, digits);
            System.out.println(otp);
            boolean success = TokenUtils.verifyTOTP(key, timeInMillis, period, digits, otp, window);
            System.out.println(success);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
