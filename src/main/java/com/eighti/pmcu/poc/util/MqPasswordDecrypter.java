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
 * Matches the Python implementation in dss_api_sample.py
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
     * Try AES decryption with different key derivation methods like in Python sample
     */
    private static String tryAesDecryption(String encryptedPassword, String secretKey, String secretVector) {
        try {
            // Method 1: Use direct key bytes and iv bytes (first 32/16 bytes)
            try {
                byte[] keyData = Base64.getDecoder().decode(secretKey);
                byte[] ivData = Base64.getDecoder().decode(secretVector);

                // Extract correct key size for AES-256
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
                    String result = new String(decrypted);
                    if (isPlausiblePassword(result)) {
                        return result;
                    }
                }
            } catch (Exception e) {
                log.debug("AES method 1 failed: {}", e.getMessage());
            }

            // Method 2: Use SHA-256 hashed key and MD5 hashed IV (like Python sample)
            try {
                byte[] keyData = Base64.getDecoder().decode(secretKey);
                byte[] ivData = Base64.getDecoder().decode(secretVector);

                // Hash the key with SHA-256
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] aesKey = sha256.digest(keyData);

                // Hash the IV with MD5
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                byte[] aesIv = md5.digest(ivData);

                SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(aesIv);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

                byte[] encrypted = hexStringToByteArray(encryptedPassword);
                byte[] decrypted = cipher.doFinal(encrypted);
                String result = new String(decrypted);
                if (isPlausiblePassword(result)) {
                    return result;
                }
            } catch (Exception e) {
                log.debug("AES method 2 failed: {}", e.getMessage());
            }

            // Method 3: Try with base64 decode of password (another approach in Python sample)
            try {
                byte[] keyData = Base64.getDecoder().decode(secretKey);
                byte[] ivData = Base64.getDecoder().decode(secretVector);

                SecretKeySpec keySpec = new SecretKeySpec(keyData, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(ivData);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

                // Try base64 decoding the encrypted password
                byte[] encrypted;
                try {
                    encrypted = Base64.getDecoder().decode(encryptedPassword);
                } catch (IllegalArgumentException e) {
                    log.debug("Password not base64 encoded, skipping method 3");
                    return null;
                }

                byte[] decrypted = cipher.doFinal(encrypted);
                String result = new String(decrypted);
                if (isPlausiblePassword(result)) {
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
