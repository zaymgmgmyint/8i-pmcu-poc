package com.eighti.pmcu.poc.service;

import com.eighti.pmcu.poc.exception.DssServiceException;
import com.eighti.pmcu.poc.request.FirstLoginRequest;
import com.eighti.pmcu.poc.request.KeepAliveRequest;
import com.eighti.pmcu.poc.request.SecondLoginRequest;
import com.eighti.pmcu.poc.response.FirstLoginResponse;
import com.eighti.pmcu.poc.response.GetMqConfigResponse;
import com.eighti.pmcu.poc.response.SecondLoginResponse;
import com.eighti.pmcu.poc.util.MqPasswordDecrypter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * AGENT: For DSS API integration
 * See: docs/dss-api-spec.md, dss_api_sample.py, dss_mq_sample.py
 * See java implementation in docs/encryption_decryption.md
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DssService {

    @Value("${dss.base-url}")
    private String baseUrl;

    @Value("${dss.username}")
    private String userName;

    @Value("${dss.password}")
    private String password;

    @Value("${dss.client-type}")
    private String clientType;

    @Value("${client-ip}")
    private String clientIp;

    // Holds the live token for the app
    private final AtomicReference<String> currentToken = new AtomicReference<>();

    @Value("${dss.keepalive-interval-ms:30000}")
    private long keepAliveInterval;

    private final RestTemplate restTemplate; // Inject SSL-configured RestTemplate

    // Store the last generated base64 secretKey and secretVector for MQ decryption
    private String lastPlainSecretKey;
    private String lastPlainSecretVector;

    public FirstLoginResponse firstLogin() {
        String url = baseUrl + "/brms/api/v1.0/accounts/authorize";

        // Create headers - NO BASIC AUTH NEEDED
        HttpHeaders headers = new HttpHeaders();
        headers.set("Accept-Language", "en");
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("User-Agent", "Spring Boot Application/1.0");
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

        // Create request body matching your Postman request
        FirstLoginRequest authRequest = new FirstLoginRequest();
        authRequest.setUserName(userName);
        authRequest.setIpAddress(clientIp);  // This was "ipAddress" in Postman
        authRequest.setClientType(clientType);

        HttpEntity<FirstLoginRequest> requestEntity = new HttpEntity<>(authRequest, headers);

        log.info("Initiating first login request to DSS at {} for user: {}", url, userName);
        log.info("Request body: {}", authRequest);
        log.info("Request headers: {}", headers.toSingleValueMap());

        try {
            ResponseEntity<FirstLoginResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    FirstLoginResponse.class
            );

            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                FirstLoginResponse response = responseEntity.getBody();
                log.info("✅ Response body: {}", response);
                log.info("✅ First login successful for user: {}. Status: {}", userName, responseEntity.getStatusCode());
                return response;
            } else if (responseEntity.getStatusCode().value() == 401) {
                // For 401, we extract the challenge payload (realm, randomKey, publicKey)
                // This works because our custom RestTemplate error handler allows 401 responses
                FirstLoginResponse response = responseEntity.getBody();
                // Debug: log headers and raw body for troubleshooting
                log.warn("401 headers: {}", responseEntity.getHeaders());
                try {
                    // Try to log the raw response as String for debugging
                    ResponseEntity<String> rawResponse = restTemplate.exchange(
                        url,
                        HttpMethod.POST,
                        requestEntity,
                        String.class
                    );
                    log.warn("401 raw body as String: {}", rawResponse.getBody());
                } catch (Exception ex) {
                    log.warn("Could not log raw 401 body as String: {}", ex.getMessage());
                }
                if (response != null) {
                    log.info("✅ First login returned challenge payload. Status: {}", responseEntity.getStatusCode());
                    log.info("Challenge payload: {}", response);
                    return response;
                } else {
                    log.warn("❌ First login returned 401 but no challenge payload. User: {}", userName);
                    throw new DssServiceException("First login failed: 401 Unauthorized with no challenge payload", null);
                }
            } else {
                log.warn("❌ First login failed for user: {}. Status: {}, Response: {}", userName, responseEntity.getStatusCode(), responseEntity);
                throw new DssServiceException("First login failed: " + responseEntity.getStatusCode(), null);
            }

        // This catch block should only execute if RestTemplate error handler isn't working properly
        // or for connection issues, since 401 responses should be handled above
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.error("❌ 401 Unauthorized slipped through error handler. DSS response body: {}", e.getResponseBodyAsString());
            }
            log.error("❌ HTTP error during first login request to DSS for user: {}. Status: {}, Response: {}", userName, e.getStatusCode(), e.getResponseBodyAsString(), e);
            throw new DssServiceException("HTTP error during first login request to DSS: " + e.getStatusCode(), e);
        } catch (RestClientException ex) {
            log.error("❌ Error during first login request to DSS for user: {}. Exception: {}", userName, ex.getMessage(), ex);
            throw new DssServiceException("❌ Error during first login request to DSS", ex);
        }
    }

    public SecondLoginResponse secondLogin() {
        try {
            // Step 1: Perform first login to get realm, randomKey, and publicKey
            FirstLoginResponse firstLoginResponse = firstLogin();
            String realm = firstLoginResponse.getRealm();
            String randomKey = firstLoginResponse.getRandomKey();
            String publicKey = firstLoginResponse.getPublicKey();

            // Step 2: Calculate signature as per Dahua API
            String temp1 = md5(password);
            String temp2 = md5(userName + temp1);
            String temp3 = md5(temp2);
            String temp4 = md5(userName + ":" + realm + ":" + temp3);
            String signature = md5(temp4 + ":" + randomKey);

            // Step 3: Create the second login request - MATCH Python implementation exactly
            String url = baseUrl + "/brms/api/v1.0/accounts/authorize";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept-Language", "en");
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("User-Agent", "Spring Boot Application/1.0");
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

            SecondLoginRequest secondLoginRequest = new SecondLoginRequest();
            secondLoginRequest.setSignature(signature);
            secondLoginRequest.setUserName(userName);
            secondLoginRequest.setRandomKey(randomKey);
            secondLoginRequest.setEncryptType("MD5");
            secondLoginRequest.setIpAddress(clientIp);
            secondLoginRequest.setClientType(clientType);
            secondLoginRequest.setPublicKey(publicKey);
            secondLoginRequest.setUserType("0");

            log.info("Second login request: {}", secondLoginRequest);

            HttpEntity<SecondLoginRequest> requestEntity = new HttpEntity<>(secondLoginRequest, headers);

            log.info("Initiating second login request to DSS at {} for user: {}", url, userName);

            ResponseEntity<SecondLoginResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    SecondLoginResponse.class
            );

            SecondLoginResponse response = responseEntity.getBody();
            log.info("✅ Second login response: {}", response);

            if (response != null && response.getToken() != null) {
                // Store token for keep-alive and other authenticated requests
                currentToken.set(response.getToken());

                // CRITICAL FIX: Store secretKey/secretVector returned by DSS for MQ decryption
                this.lastPlainSecretKey = response.getSecretKey();
                this.lastPlainSecretVector = response.getSecretVector();

                log.info("✅ Second login successful. Token stored.");
                log.info("SecretKey from DSS: {}", this.lastPlainSecretKey != null ? "Present" : "NULL");
                log.info("SecretVector from DSS: {}", this.lastPlainSecretVector != null ? "Present" : "NULL");
            } else {
                log.warn("⚠️ Second login successful but no token received");
            }
            return response;

        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("❌ HTTP error during second login request to DSS for user: {}. Status: {}, Response: {}", userName, e.getStatusCode(), e.getResponseBodyAsString(), e);
            throw new DssServiceException("HTTP error during second login request to DSS: " + e.getStatusCode(), e);
        } catch (RestClientException ex) {
            log.error("❌ Error during second login request to DSS for user: {}. Exception: {}", userName, ex.getMessage(), ex);
            throw new DssServiceException("Error during second login request to DSS", ex);
        }
    }

    public SecondLoginResponse secondLogin1() {
        try {
            // Step 1: Perform first login to get realm, randomKey, and publicKey
            FirstLoginResponse firstLoginResponse = firstLogin();
            String realm = firstLoginResponse.getRealm();
            String randomKey = firstLoginResponse.getRandomKey();
            String publicKey = firstLoginResponse.getPublicKey();

            // Step 2: Calculate signature as per Dahua API
            String temp1 = md5(password);
            String temp2 = md5(userName + temp1);
            String temp3 = md5(temp2);
            String temp4 = md5(userName + ":" + realm + ":" + temp3);
            String signature = md5(temp4 + ":" + randomKey);

            // Step 3: Create the second login request - MATCH Python implementation exactly
            String url = baseUrl + "/brms/api/v1.0/accounts/authorize";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept-Language", "en");
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("User-Agent", "Spring Boot Application/1.0");
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

            // Generate your own AES key + IV for MQ password decryption later
            byte[] aesKeyBytes    = new byte[32];  // 256-bit
            byte[] aesIvBytes     = new byte[16];  // 128-bit
            new SecureRandom().nextBytes(aesKeyBytes);
            new SecureRandom().nextBytes(aesIvBytes);

            // Base64-encode them and stash for your decryptor
            String plainAesKey     = Base64.getEncoder().encodeToString(aesKeyBytes);
            String plainAesVector  = Base64.getEncoder().encodeToString(aesIvBytes);

            // keep them for your later MQ‐password decrypt
            this.lastPlainSecretKey    = plainAesKey;    // stash for MQ decrypt
            this.lastPlainSecretVector = plainAesVector; // stash for MQ decrypt

            // RSA‐encrypt them with the DSS publicKey
            String encryptedKey    = rsaEncryptWithDssPublicKey1(plainAesKey, publicKey);
            String encryptedVector = rsaEncryptWithDssPublicKey1(plainAesVector, publicKey);

            // AGENT: Debug logging for encrypted keys
            log.info("🔐 Generated AES credentials:");
            log.info("Plain AES Key length: {} bytes", aesKeyBytes.length);
            log.info("Plain AES IV length: {} bytes", aesIvBytes.length);
            log.info("Base64 AES Key length: {} chars", plainAesKey.length());
            log.info("Base64 AES IV length: {} chars", plainAesVector.length());
            log.info("RSA Encrypted Key length: {} chars", encryptedKey.length());
            log.info("RSA Encrypted Vector length: {} chars", encryptedVector.length());

            SecondLoginRequest secondLoginRequest = new SecondLoginRequest();
            secondLoginRequest.setSignature(signature);
            secondLoginRequest.setUserName(userName);
            secondLoginRequest.setRandomKey(randomKey);
            secondLoginRequest.setEncryptType("MD5");
            secondLoginRequest.setIpAddress(clientIp);
            secondLoginRequest.setClientType(clientType);
            secondLoginRequest.setPublicKey(publicKey);
            secondLoginRequest.setUserType("0");
            // RSA-encrypted AES credentials
            secondLoginRequest.setSecretKey(encryptedKey);
            secondLoginRequest.setSecretVector(encryptedVector);

            log.info("Second login request: {}", secondLoginRequest);

            HttpEntity<SecondLoginRequest> requestEntity = new HttpEntity<>(secondLoginRequest, headers);

            log.info("Initiating second login request to DSS at {} for user: {}", url, userName);

            ResponseEntity<SecondLoginResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    SecondLoginResponse.class
            );

            SecondLoginResponse response = responseEntity.getBody();
            log.info("✅ Second login response: {}", response);

            if (response != null && response.getToken() != null) {
                // Store token for keep-alive and other authenticated requests
                currentToken.set(response.getToken());
                log.info("✅ Second login successful. Token stored.");
                log.info("SecretKey from DSS: {}", this.lastPlainSecretKey != null ? "Present" : "NULL");
                log.info("SecretVector from DSS: {}", this.lastPlainSecretVector != null ? "Present" : "NULL");
            } else {
                log.warn("⚠️ Second login successful but no token received");
            }
            return response;

        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("❌ HTTP error during second login request to DSS for user: {}. Status: {}, Response: {}", userName, e.getStatusCode(), e.getResponseBodyAsString(), e);
            throw new DssServiceException("HTTP error during second login request to DSS: " + e.getStatusCode(), e);
        } catch (RestClientException ex) {
            log.error("❌ Error during second login request to DSS for user: {}. Exception: {}", userName, ex.getMessage(), ex);
            throw new DssServiceException("Error during second login request to DSS", ex);
        }
    }

    /**
     * RSA encrypt data with DSS platform public key
     * This replicates what the Python sample does with:
     * rsa_key = serialization.load_der_public_key(base64.b64decode(publicKey))
     * encrypted = rsa_key.encrypt(data, padding.PKCS1v15())
     */
    private String rsaEncryptWithDssPublicKey(String plaintext, String base64PublicKey) {
        try {
            // Decode the base64 public key from DSS
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);

            // Create a public key object
            java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Create cipher and encrypt
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

            // Return base64 encoded encrypted bytes
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            log.error("RSA encryption failed: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to RSA encrypt with DSS public key", e);
        }
    }

    /**
     * RSA encrypt data with DSS platform public key (PKCS#1 v1.5 padding).
     * Splits into 245-byte chunks for a 2048-bit key.
     */
    private String rsaEncryptWithDssPublicKey1(String plaintext, String base64PublicKey) {
        try {
            byte[] der = Base64.getDecoder().decode(base64PublicKey);
            PublicKey pub = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, pub);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
            int blockSize = 245; // for 2048-bit key
            for (int off = 0; off < data.length; off += blockSize) {
                int len = Math.min(blockSize, data.length - off);
                out.write(c.doFinal(data, off, len));
            }
            return Base64.getEncoder().encodeToString(out.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("RSA encryption failed", e);
        }
    }


    // Send keep alive to DSS
    public void sendKeepAlive() {
        String token = currentToken.get();
        if (token == null) {
            log.error("❌ Failed to get token from DSS");
            throw new IllegalStateException("❌ No token available—must login first");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Subject-Token", token);

        restTemplate.exchange(
                baseUrl + "/brms/api/v1.0/accounts/keepAlive",
                HttpMethod.POST,
                new HttpEntity<>(new KeepAliveRequest(token), headers),
                Void.class
        );
    }

    // Schedule the keep alive task
    @Scheduled(fixedDelayString = "#{dssService.keepAliveInterval}")
    public void scheduleKeepAlive() {
        try{
            sendKeepAlive();
            log.info("✅ Keep alive sent to DSS");
        }catch (Exception e) {
            log.error("❌ Keep-alive failed to DSS, will retry on next schedule: {}", e.getMessage(), e);
        }
    }

    private String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("MD5 calculation failed", e);
        }
    }

    // Getting the MQ Config from DSS Endpoint
    public GetMqConfigResponse getMqConfig() {
        try {
            // Check if we already have a valid token
            String token = currentToken.get();

            // If no token exists, perform full login
            if (token == null) {
                log.info("No existing token, performing full login sequence");
                SecondLoginResponse secondLoginResponse = secondLogin1(); // AGENT: Use the correct method
                token = secondLoginResponse.getToken();

                if (token == null) {
                    log.error("❌ Failed to get token from DSS");
                    throw new DssServiceException("Failed to get token from DSS", null);
                }
            }

            String url = baseUrl + "/brms/api/v1.0/BRM/Config/GetMqConfig";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept-Language", "en");
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-Subject-Token", token);

            // Use an empty map which Jackson will serialize to {}
            HttpEntity<Map<String,Object>> requestEntity =
                    new HttpEntity<>(Collections.emptyMap(), headers);

            log.info("Getting MQ config from DSS at {}", url);

            try {
                ResponseEntity<GetMqConfigResponse> responseEntity = restTemplate.exchange(
                        url,
                        HttpMethod.POST,
                        requestEntity,
                        GetMqConfigResponse.class
                );

                GetMqConfigResponse response = responseEntity.getBody();
                log.info("Response from DSS: {}", response);
                log.info("✅ Retrieved raw MQ config. Status: {}", responseEntity.getStatusCode());

                // Attempt to decrypt password if present
                if (response != null && response.getData() != null && response.getData().getPassword() != null) {
                    String encryptedPassword = response.getData().getPassword();
                    log.info("Encrypted MQ password found: {}", encryptedPassword);

                    // Try to decrypt the password using our utility
                    String decryptedPassword = MqPasswordDecrypter.decryptMqPassword(
                            encryptedPassword,
                            lastPlainSecretKey,
                            lastPlainSecretVector
                    );

                    if (decryptedPassword != null) {
                        log.info("✅ Successfully decrypted MQ password");
                        // Update the password in the response object
                        response.getData().setPassword(decryptedPassword);
                    } else {
                        log.warn("⚠️ Failed to decrypt MQ password - returning original encrypted value");
                    }
                } else {
                    log.warn("⚠️ No MQ password found in response");
                }

                log.info("✅ Successfully processed MQ config");
                return response;

            } catch (org.springframework.web.client.HttpClientErrorException e) {
                // Handle case where token might have expired
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                    log.warn("Token expired or invalid, performing new login");
                    // Try again with a fresh token
                    SecondLoginResponse secondLoginResponse = secondLogin();
                    token = secondLoginResponse.getToken();

                    // Update headers with new token
                    headers.set("X-Subject-Token", token);
                    requestEntity = new HttpEntity<>(Collections.emptyMap(), headers);

                    // Retry the request
                    ResponseEntity<GetMqConfigResponse> responseEntity = restTemplate.exchange(
                            url,
                            HttpMethod.POST,
                            requestEntity,
                            GetMqConfigResponse.class
                    );

                    GetMqConfigResponse response = responseEntity.getBody();

                    // Attempt to decrypt password after token refresh
                    if (response != null && response.getData() != null && response.getData().getPassword() != null) {
                        String encryptedPassword = response.getData().getPassword();
                        String decryptedPassword = MqPasswordDecrypter.decryptMqPassword(
                                encryptedPassword,
                                lastPlainSecretKey,
                                lastPlainSecretVector
                        );

                        if (decryptedPassword != null) {
                            log.info("✅ Successfully decrypted MQ password after token refresh");
                            response.getData().setPassword(decryptedPassword);
                        }
                    }

                    log.info("✅ Successfully retrieved MQ config after token refresh. Status: {}", responseEntity.getStatusCode());
                    return response;
                } else {
                    // Other HTTP error
                    log.error("❌ HTTP error getting MQ config. Status: {}, Response: {}", e.getStatusCode(), e.getResponseBodyAsString());
                    throw new DssServiceException("HTTP error getting MQ config: " + e.getStatusCode(), e);
                }
            }
        } catch (RestClientException e) {
            log.error("❌ Error getting MQ config", e);
            throw new DssServiceException("Error getting MQ config", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Generate a random alphanumeric string of given length
     */
    private String generateRandomAlphaNum(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz"
                + "0123456789";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * Returns the last generated base64-encoded secretKey for MQ decryption
     */
    public String getPlainSecretKey() {
        return lastPlainSecretKey;
    }

    /**
     * Returns the last generated base64-encoded secretVector for MQ decryption
     */
    public String getPlainSecretVector() {
        return lastPlainSecretVector;
    }

    // AGENT: Expose the current DSS session token for API calls
    public String getCurrentToken() {
        return currentToken.get();
    }


}
