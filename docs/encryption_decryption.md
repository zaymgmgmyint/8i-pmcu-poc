# GitHub Copilot: Implement §6.4 Encryption & Decryption Example

Below are detailed instructions to guide you in generating the Java methods exactly as described in Dahua HTTP API for DSS V8.6, section **6.4 Encryption and Decryption Example**.  Please produce fully compilable JDK 1.8+ code, with appropriate imports and `throws Exception` clauses.

---

## 1. MD5 Encryption

```java
/**
 * MD5-encrypts a UTF-8 string.
 * @param text Plain text to hash
 * @return Lower-case hex MD5 digest
 * @throws Exception
 */
public static String encryptByMd5(String text) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
        sb.append(String.format("%02x", b));
    }
    return sb.toString();
}
```

# 2. RSA Key Generation

```java
/**
 * Generates a 2048-bit RSA key pair.
 * Private key in PKCS#8, public key in X.509.
 * @return KeyPair
 * @throws Exception
 */
public static KeyPair getRsaKeys() throws Exception {
    Provider prov = Security.getProvider("SunRsaSign");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", prov);
    kpg.initialize(2048, new SecureRandom());
    return kpg.generateKeyPair();
}
```

# 3. RSA Encryption & Decryption

```java
/**
 * RSA public-key encrypt (ECB/PKCS1Padding). Split input in 245-byte chunks.
 * @param plain  UTF-8 text
 * @param pubKey X.509-encoded public key bytes
 * @return raw cipher bytes
 * @throws Exception
 */
public static byte[] encryptByPublicKey(String plain, byte[] pubKey) throws Exception {
    X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKey);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    PublicKey pk = kf.generatePublic(spec);
    Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    c.init(Cipher.ENCRYPT_MODE, pk);

    byte[] data = plain.getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int chunkSize = 245;
    for (int i = 0; i < data.length; i += chunkSize) {
        int end = Math.min(i + chunkSize, data.length);
        out.write(c.doFinal(Arrays.copyOfRange(data, i, end)));
    }
    return out.toByteArray();
}

/**
 * RSA private-key decrypt (ECB/PKCS1Padding). Split input in 256-byte chunks.
 * @param hexCipher  Hex string of RSA output
 * @param privKeyPK8 PKCS#8-encoded private key bytes
 * @return decrypted UTF-8 bytes
 * @throws Exception
 */
public static byte[] decryptByPrivateKey(String hexCipher, byte[] privKeyPK8) throws Exception {
    byte[] cipherBytes = parseHexStr2Byte(hexCipher);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privKeyPK8);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    PrivateKey pk = kf.generatePrivate(spec);

    Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    c.init(Cipher.DECRYPT_MODE, pk);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int chunkSize = 256;
    for (int i = 0; i < cipherBytes.length; i += chunkSize) {
        int end = Math.min(i + chunkSize, cipherBytes.length);
        out.write(c.doFinal(Arrays.copyOfRange(cipherBytes, i, end)));
    }
    return out.toByteArray();
}
```

# 4. AES/CBC/PKCS7 Padding
- Note: If BouncyCastle is unavailable, switch "AES/CBC/PKCS7Padding" → "AES/CBC/PKCS5Padding".
```java
/**
 * AES-CBC encrypt (PKCS7Padding) → hex string (lower-case).
 * @param plain      UTF-8 text
 * @param aesKeyHex  32-byte hex key
 * @param aesIvHex   16-byte hex IV
 * @return hex cipher (lower-case)
 * @throws Exception
 */
public static String encryptByAesCbc(String plain, String aesKeyHex, String aesIvHex) throws Exception {
    byte[] key = parseHexStr2Byte(aesKeyHex);
    byte[] iv  = parseHexStr2Byte(aesIvHex);
    Security.addProvider(new BouncyCastleProvider());
    SecretKeySpec ks = new SecretKeySpec(key, "AES");
    IvParameterSpec vs = new IvParameterSpec(iv);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
    c.init(Cipher.ENCRYPT_MODE, ks, vs);
    byte[] encrypted = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
    return parseByte2HexStr(encrypted);
}

/**
 * AES-CBC decrypt (PKCS7Padding).
 * @param hexCipher  lower-case hex string
 * @param aesKeyHex  32-byte hex key
 * @param aesIvHex   16-byte hex IV
 * @return decrypted UTF-8 text
 * @throws Exception
 */
public static String decryptByAesCbc(String hexCipher, String aesKeyHex, String aesIvHex) throws Exception {
    byte[] key = parseHexStr2Byte(aesKeyHex);
    byte[] iv  = parseHexStr2Byte(aesIvHex);
    Security.addProvider(new BouncyCastleProvider());
    SecretKeySpec ks = new SecretKeySpec(key, "AES");
    IvParameterSpec vs = new IvParameterSpec(iv);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
    c.init(Cipher.DECRYPT_MODE, ks, vs);
    byte[] decrypted = c.doFinal(parseHexStr2Byte(hexCipher));
    return new String(decrypted, StandardCharsets.UTF_8);
}
```
# 5. Utility Functions

```java/** Convert lower-case hex to bytes. */
private static byte[] parseHexStr2Byte(String hex) {
  int len = hex.length() / 2;
  byte[] result = new byte[len];
  for (int i = 0; i < len; i++) {
    int high = Integer.parseInt(hex.substring(2*i,   2*i+1), 16);
    int low  = Integer.parseInt(hex.substring(2*i+1, 2*i+2), 16);
    result[i] = (byte)(high*16 + low);
  }
  return result;
}

/** Convert bytes to lower-case hex string. */
private static String parseByte2HexStr(byte[] bytes) {
  StringBuilder sb = new StringBuilder(bytes.length * 2);
  for (byte b : bytes) {
    sb.append(String.format("%02x", b));
  }
  return sb.toString();
}

/** Merge two byte arrays. */
private static byte[] sumBytes(byte[] a, byte[] b) {
  byte[] out = new byte[(a==null?0:a.length) + (b==null?0:b.length)];
  if (a!=null) System.arraycopy(a, 0, out, 0, a.length);
  if (b!=null) System.arraycopy(b, 0, out, a.length, b.length);
  return out;
}
```

# Additional Notes

- Ensure all imports (java.security.*, javax.crypto.*, org.bouncycastle.jce.provider.BouncyCastleProvider, etc.) are present.