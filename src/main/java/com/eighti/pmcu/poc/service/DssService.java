package com.eighti.pmcu.poc.service;

import com.eighti.pmcu.poc.exception.DssServiceException;
import com.eighti.pmcu.poc.request.FirstLoginRequest;
import com.eighti.pmcu.poc.request.KeepAliveRequest;
import com.eighti.pmcu.poc.request.SecondLoginRequest;
import com.eighti.pmcu.poc.response.FirstLoginResponse;
import com.eighti.pmcu.poc.response.GetMqConfigResponse;
import com.eighti.pmcu.poc.response.SecondLoginResponse;
import com.eighti.pmcu.poc.util.CommonHelper;
import com.eighti.pmcu.poc.util.MqPasswordDecrypter;
import com.eighti.pmcu.poc.util.RSAEncryptionDecryption;
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
 * For DSS API integration
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
            String platformPublicKey = firstLoginResponse.getPublicKey();

            // Step 2: Calculate signature as per Dahua API
            String temp1 = encryptByMd5(password);
            String temp2 = encryptByMd5(userName + temp1);
            String temp3 = encryptByMd5(temp2);
            String temp4 = encryptByMd5(userName + ":" + realm + ":" + temp3);
            String signature = encryptByMd5(temp4 + ":" + randomKey);

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
            secondLoginRequest.setPublicKey("");
            secondLoginRequest.setUserType("0");

            // Generate random secretKey (32 characters) and secretVector (16 characters)
            String secretKeyPlain = CommonHelper.generateRandomString(32);
            String secretVectorPlain = CommonHelper.generateRandomString(16);

            // Convert Base64-encoded platformPublicKey from first login into PublicKey object
            PublicKey rsaPublicKey = CommonHelper.getPublicKeyFromBase64(platformPublicKey);

            // Encrypt the AES key and IV using platform's public RSA key
            byte[] encryptedSecretKeyBytes = RSAEncryptionDecryption.encryptByPublicKey(secretKeyPlain, rsaPublicKey.getEncoded());
            byte[] encryptedSecretVectorBytes = RSAEncryptionDecryption.encryptByPublicKey(secretVectorPlain, rsaPublicKey.getEncoded());

            // Convert encrypted bytes to HEX string format (required by DSS API)
            String encryptedSecretKeyHex = RSAEncryptionDecryption.parseByte2HexStr(encryptedSecretKeyBytes).toUpperCase();
            String encryptedSecretVectorHex = RSAEncryptionDecryption.parseByte2HexStr(encryptedSecretVectorBytes).toUpperCase();

            System.out.println("Encrypted SecretKey: " + encryptedSecretKeyHex);
            System.out.println("Encrypted SecretVector: " + encryptedSecretVectorHex);

            // RSA-encrypted AES credentials
            secondLoginRequest.setSecretKey(encryptedSecretKeyHex);
            secondLoginRequest.setSecretVector(encryptedSecretVectorHex);

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
            log.error("❌ Error during second login request to DSS for user: {}. RestClientException: {}", userName, ex.getMessage(), ex);
            throw new DssServiceException("Error during second login request to DSS", ex);
        } catch (Exception e) {
            log.error("❌ Error during second login request to DSS for user: {}. Exception: {}", userName, e.getMessage(), e);
            throw new RuntimeException(e);
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

    // Getting the MQ Config from DSS Endpoint
    public GetMqConfigResponse getMqConfig() {
        try {
            // Check if we already have a valid token
            String token = currentToken.get();

            // If no token exists, perform full login
            if (token == null) {
                log.info("No existing token, performing full login sequence");
                SecondLoginResponse secondLoginResponse = secondLogin(); // Use the correct method
                token = secondLoginResponse.getToken();

                if (token == null) {
                    log.error("❌ Failed to get token from DSS");
                    throw new DssServiceException("Failed to get token from DSS", null);
                }
            }

            String url = baseUrl + "/brms/api/v1.0/BRM/Config/GetMqConfig";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept-Language", "en");
            headers.set("Content-Type", "application/json;charset=UTF-8");
            headers.set("X-Subject-Token", token);

            // Use an empty map which Jackson will serialize to {}
            HttpEntity<String> requestEntity = new HttpEntity<>("{}", headers);

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
                    requestEntity = new HttpEntity<>("{}", headers);

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

    // Expose the current DSS session token for API calls
    public String getCurrentToken() {
        return currentToken.get();
    }


}
