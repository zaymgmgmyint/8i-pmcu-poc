package com.eighti.pmcu.poc.util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Encryption {

    /**
     * MD5 encryption
     * @param text data
     * @return string after encryption
     * @throws Exception
     */
    public static String encryptByMd5(String text) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] messageDigest = md.digest(text.getBytes());
        StringBuilder buffer = new StringBuilder();
        for (byte b : messageDigest) {
            buffer.append(String.format("%02x", b));
        }
        return buffer.toString();
    }
}
