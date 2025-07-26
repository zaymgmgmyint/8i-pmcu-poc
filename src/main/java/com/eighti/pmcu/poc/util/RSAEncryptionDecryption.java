package com.eighti.pmcu.poc.util;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class RSAEncryptionDecryption {

    /**
     * Generate RSA public key and private key. The private key is in pkcs8 format, and the public key is in X509 format
     * @return key pair
     * @throws Exception
     */
    public static KeyPair getRsaKeys() throws Exception {
        Provider provider = Security.getProvider("SunRsaSign");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", provider);
        keyPairGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        return keyPair;
    }

    /**
     * RSA encryption. Public key encryption, private key decryption
     * @param text data
     * @param publicKeyBytes public key string array
     * @return string after encryption
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(String text, byte[] publicKeyBytes) throws Exception {
        byte[] result = null;
        int rsaBytesLenEncrypt = 245;

        // Get public key object
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicKeyObject = keyFactory.generatePublic(x509KeySpec);

        // Encrypt data
        byte[] dataBytes = text.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyObject);
        for (int i = 0; i < dataBytes.length; i += rsaBytesLenEncrypt) {
            int to = Math.min(i + rsaBytesLenEncrypt, dataBytes.length);
            byte[] temp = cipher.doFinal(Arrays.copyOfRange(dataBytes, i, to));
            result = sumBytes(result, temp);
        }

        return result;
    }

    /**
     * RSA decryption. Public key encryption, private key decryption
     * @param text data
     * @param privateKeyBytes private key string array
     * @return string after decryption
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(String text, byte[] privateKeyBytes) throws Exception {
        byte[] result = null;
        int rsaBytesLenDecrypt = 256;
        byte[] dataBytes = parseHexStr2Byte(text);

        // Get private key object
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // Decrypt data
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        for (int i = 0; i < dataBytes.length; i += rsaBytesLenDecrypt) {
            int to = (i + rsaBytesLenDecrypt) < dataBytes.length ? (i + rsaBytesLenDecrypt) : dataBytes.length;
            byte[] temp = cipher.doFinal(Arrays.copyOfRange(dataBytes, i, to));
            result = sumBytes(result, temp);
        }

        return result;
    }

    /**
     * Byte array to hex string
     * @param bytes byte array
     * @return hex string
     */
    public static String parseByte2HexStr(byte[] bytes) {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            buffer.append(hex);
        }
        return buffer.toString();
    }

    /**
     * Hex string to byte array
     * @param hexStr hex string
     * @return byte array
     */
    private static byte[] parseHexStr2Byte(String hexStr) {
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }


    /**
     * Sum 2 bytes
     * @param bytes1 byte 1
     * @param bytes2 byte 2
     * @return the new array formed by merging two arrays
     */
    private static byte[] sumBytes(byte[] bytes1, byte[] bytes2) {
        byte[] result = null;
        int len1 = 0;
        int len2 = 0;
        if (null != bytes1) {
            len1 = bytes1.length;
        }
        if (null != bytes2) {
            len2 = bytes2.length;
        }
        if (len1 + len2 > 0) {
            result = new byte[len1 + len2];
        }
        if (len1 > 0) {
            System.arraycopy(bytes1, 0, result, 0, len1);
        }
        if (len2 > 0) {
            System.arraycopy(bytes2, 0, result, len1, len2);
        }
        return result;
    }
}
