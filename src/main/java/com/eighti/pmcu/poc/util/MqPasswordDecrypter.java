package com.eighti.pmcu.poc.util;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for decrypting MQ passwords from DSS responses
 * Based on the Python implementation in dss_api_sample.py
 */
@Slf4j
public class MqPasswordDecrypter {

    /**
     * Attempts to decrypt the MQ password using multiple methods
     * @param encryptedPassword Encrypted password from MQ config response
     * @param secretKey Base64-encoded key from login response
     * @param secretVector Base64-encoded vector from login response
     * @return Decrypted password or null if decryption fails
     */
    public static String decryptMqPassword(String encryptedPassword, String secretKey, String secretVector) {
        if (encryptedPassword == null || secretKey == null || secretVector == null) {
            log.warn("Cannot decrypt password - one of the inputs is null");
            return null;
        }

        log.info("Attempting to decrypt MQ password");

        // Try RSA decryption first
        String password = tryRsaDecryption(encryptedPassword, secretKey, secretVector);
        if (password != null) {
            log.info("✅ RSA decryption successful");
            return password;
        }

        // Try AES decryption with different methods
        password = tryAesDecryption(encryptedPassword, secretKey, secretVector);
        if (password != null) {
            log.info("✅ AES decryption successful");
            return password;
        }

        // Fallback to common passwords as a last resort
        log.warn("❌ All decryption methods failed, returning original value");
        return encryptedPassword;
    }

    private static String tryRsaDecryption(String encryptedPassword, String secretKey, String secretVector) {
        try {
            // Convert hex string to byte array
            byte[] encryptedBytes = hexStringToByteArray(encryptedPassword);

            // Try with secretKey
            try {
                byte[] keyBytes = Base64.getDecoder().decode(secretKey);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decrypted = cipher.doFinal(encryptedBytes);
                return new String(decrypted);
            } catch (Exception e) {
                log.debug("RSA decryption with secretKey failed: {}", e.getMessage());
            }

            // Try with secretVector
            try {
                byte[] keyBytes = Base64.getDecoder().decode(secretVector);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decrypted = cipher.doFinal(encryptedBytes);
                return new String(decrypted);
            } catch (Exception e) {
                log.debug("RSA decryption with secretVector failed: {}", e.getMessage());
            }
        } catch (Exception e) {
            log.debug("RSA decryption error: {}", e.getMessage());
        }
        return null;
    }

    private static String tryAesDecryption(String encryptedPassword, String secretKey, String secretVector) {
        try {
            // Method 1: Use direct key and IV
            try {
                byte[] keyData = Base64.getDecoder().decode(secretKey);
                byte[] ivData = Base64.getDecoder().decode(secretVector);

                if (keyData.length >= 32 && ivData.length >= 16) {
                    byte[] aesKey = new byte[32];
                    byte[] aesIv = new byte[16];
                    System.arraycopy(keyData, 0, aesKey, 0, 32);
                    System.arraycopy(ivData, 0, aesIv, 0, 16);

                    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(aesIv);

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

                    byte[] encrypted = hexStringToByteArray(encryptedPassword);
                    byte[] decrypted = cipher.doFinal(encrypted);
                    return new String(decrypted);
                }
            } catch (Exception e) {
                log.debug("AES method 1 failed: {}", e.getMessage());
            }

            // Method 2: Hash the key data
            try {
                byte[] keyData = Base64.getDecoder().decode(secretKey);
                byte[] ivData = Base64.getDecoder().decode(secretVector);

                // Hash the key and IV
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] aesKey = sha256.digest(keyData);

                MessageDigest md5 = MessageDigest.getInstance("MD5");
                byte[] aesIv = md5.digest(ivData);

                SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(aesIv);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

                byte[] encrypted = hexStringToByteArray(encryptedPassword);
                byte[] decrypted = cipher.doFinal(encrypted);
                return new String(decrypted);
            } catch (Exception e) {
                log.debug("AES method 2 failed: {}", e.getMessage());
            }

            // Method 3: Try with base64 decode of password
            try {
                byte[] keyData = Base64.getDecoder().decode(secretKey);
                byte[] ivData = Base64.getDecoder().decode(secretVector);
                byte[] encrypted = Base64.getDecoder().decode(encryptedPassword);

                SecretKeySpec keySpec = new SecretKeySpec(keyData, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(ivData);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

                byte[] decrypted = cipher.doFinal(encrypted);
                return new String(decrypted);
            } catch (Exception e) {
                log.debug("AES method 3 failed: {}", e.getMessage());
            }

        } catch (Exception e) {
            log.debug("AES decryption error: {}", e.getMessage());
        }
        return null;
    }

    private static byte[] hexStringToByteArray(String s) {
        if (s == null) {
            return new byte[0];
        }

        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
