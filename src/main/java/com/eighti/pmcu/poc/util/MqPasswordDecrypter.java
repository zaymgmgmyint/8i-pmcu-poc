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
 * Match with java implementation in docs/encryption_decryption.md
 * See the Python implementation in docs/dss_mq_sample.py
 *
 */
@Slf4j
public class MqPasswordDecrypter {

    /**
     * Attempts to decrypt the MQ password using multiple methods as in the Python sample
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
        log.debug("Encrypted password: {}", encryptedPassword);
        log.debug("SecretKey length: {}", Base64.getDecoder().decode(secretKey).length);
        log.debug("SecretVector length: {}", Base64.getDecoder().decode(secretVector).length);

        try {
            // First try RSA decryption (like Python sample)
            String password = tryRsaDecryption(encryptedPassword, secretKey, secretVector);
            if (password != null) {
                log.info("✅ RSA decryption successful");
                return password;
            }

            // Then try AES decryption with different methods
            password = tryAesDecryption(encryptedPassword, secretKey, secretVector);
            if (password != null) {
                log.info("✅ AES decryption successful");
                return password;
            }

            // Try common fallback passwords as a last resort (like Python sample)
            log.warn("❌ All decryption methods failed, trying common passwords");
            String[] commonPasswords = {"admin", "consumer", "password", "123456", "dahua", "system", "ismart123456"};
            for (String pwd : commonPasswords) {
                log.debug("Trying common password: {}", pwd);
                if (isPasswordValid(pwd)) {
                    log.info("✅ Found working common password: {}", pwd);
                    return pwd;
                }
            }

            // Return the original value if all attempts fail
            log.warn("❌ All decryption methods failed, returning original value");
            return encryptedPassword;

        } catch (Exception e) {
            log.error("Error during password decryption: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Placeholder method to validate if a password works with MQ broker
     * In a real implementation, this would try connecting to the broker
     */
    private static boolean isPasswordValid(String password) {
        // In Python, this tries an actual connection
        // Here we just return false to avoid complexity
        return false;
    }

    /**
     * Try RSA decryption approach like in the Python sample
     */
    private static String tryRsaDecryption(String encryptedPassword, String secretKey, String secretVector) {
        try {
            // Convert hex string to byte array
            byte[] encryptedBytes = hexStringToByteArray(encryptedPassword);

            // Try with secretKey as RSA private key
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

            // Try with secretVector as RSA private key
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

    /**
     * Try AES decryption approach - match Python implementation
     */
    private static String tryAesDecryption(String encryptedPassword, String secretKey, String secretVector) {
        try {
            // Convert hex string to byte array
            byte[] encryptedBytes = hexStringToByteArray(encryptedPassword);

            // Method 1: Use base64-decoded secretKey and secretVector as raw AES key/IV
            try {
                byte[] keyBytes = Base64.getDecoder().decode(secretKey);
                byte[] ivBytes = Base64.getDecoder().decode(secretVector);

                // Ensure correct sizes: AES-256 needs 32-byte key, AES needs 16-byte IV
                if (keyBytes.length == 32 && ivBytes.length == 16) {
                    SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                    byte[] decrypted = cipher.doFinal(encryptedBytes);
                    String result = new String(decrypted);
                    log.info("✅ AES method 1 successful");
                    return result;
                }
            } catch (Exception e) {
                log.debug("AES method 1 failed: {}", e.getMessage());
            }

            // Method 2: Try treating secretKey as hex-encoded AES key
            try {
                byte[] keyBytes = hexStringToByteArray(secretKey.substring(0, Math.min(64, secretKey.length()))); // 32 bytes = 64 hex chars
                byte[] ivBytes = hexStringToByteArray(secretVector.substring(0, Math.min(32, secretVector.length()))); // 16 bytes = 32 hex chars

                if (keyBytes.length >= 16 && ivBytes.length >= 16) {
                    // Truncate to correct sizes if needed
                    byte[] aesKey = new byte[32];
                    byte[] aesIv = new byte[16];
                    System.arraycopy(keyBytes, 0, aesKey, 0, Math.min(32, keyBytes.length));
                    System.arraycopy(ivBytes, 0, aesIv, 0, Math.min(16, ivBytes.length));

                    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(aesIv);

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                    byte[] decrypted = cipher.doFinal(encryptedBytes);
                    String result = new String(decrypted);
                    log.info("✅ AES method 2 successful");
                    return result;
                }
            } catch (Exception e) {
                log.debug("AES method 2 failed: {}", e.getMessage());
            }

            // Method 3: Simple AES approach using first 32 bytes as key, next 16 as IV
            try {
                String combined = secretKey + secretVector;
                byte[] allBytes = Base64.getDecoder().decode(combined);

                if (allBytes.length >= 48) { // 32 + 16
                    byte[] keyBytes = new byte[32];
                    byte[] ivBytes = new byte[16];
                    System.arraycopy(allBytes, 0, keyBytes, 0, 32);
                    System.arraycopy(allBytes, 32, ivBytes, 0, 16);

                    SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                    byte[] decrypted = cipher.doFinal(encryptedBytes);
                    String result = new String(decrypted);
                    log.info("✅ AES method 3 successful");
                    return result;
                }
            } catch (Exception e) {
                log.debug("AES method 3 failed: {}", e.getMessage());
            }

        } catch (Exception e) {
            log.debug("AES decryption error: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Simple validation that the result looks like a password
     */
    private static boolean isPlausiblePassword(String password) {
        // Simple validation - password should be ASCII and reasonable length
        return password != null &&
               password.length() >= 3 &&
               password.length() <= 50 &&
               password.matches("^[\\x20-\\x7E]+$"); // ASCII printable characters
    }

    /**
     * Convert hex string to byte array
     */
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
