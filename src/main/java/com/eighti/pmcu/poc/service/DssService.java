package com.eighti.pmcu.poc.service;

import com.eighti.pmcu.poc.exception.DssServiceException;
import com.eighti.pmcu.poc.request.FirstLoginRequest;
import com.eighti.pmcu.poc.request.KeepAliveRequest;
import com.eighti.pmcu.poc.request.SecondLoginRequest;
import com.eighti.pmcu.poc.response.FirstLoginResponse;
import com.eighti.pmcu.poc.response.GetMqConfigResponse;
import com.eighti.pmcu.poc.response.SecondLoginResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * AGENT: See: docs/dss-api-spec.md
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
        log.debug("Request body: {}", authRequest);
        log.debug("Request headers: {}", headers.toSingleValueMap());

        try {
            ResponseEntity<FirstLoginResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    FirstLoginResponse.class
            );

            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                FirstLoginResponse response = responseEntity.getBody();
                log.info("✅ First login successful for user: {}. Status: {}", userName, responseEntity.getStatusCode());
                return response;
            } else {
                log.warn("❌ First login failed for user: {}. Status: {}, Response: {}", userName, responseEntity.getStatusCode(), responseEntity);
                throw new DssServiceException("First login failed: " + responseEntity.getStatusCode(), null);
            }

        } catch (org.springframework.web.client.HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.error("❌ 401 Unauthorized. DSS response body: {}", e.getResponseBodyAsString());
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

            // Step 2.1: Generate random secretKey (32 chars) and secretVector (16 chars)
            String plainSecretKey = generateRandomAlphaNum(32);
            String plainSecretVector = generateRandomAlphaNum(16);
            String base64SecretKey = Base64.getEncoder().encodeToString(plainSecretKey.getBytes());
            String base64SecretVector = Base64.getEncoder().encodeToString(plainSecretVector.getBytes());
            // Store for MQ decryption
            this.lastPlainSecretKey = base64SecretKey;
            this.lastPlainSecretVector = base64SecretVector;

            // Step 3: Create the second login request (to /accounts/authorize)
            String url = baseUrl + "/brms/api/v1.0/accounts/authorize";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("User-Agent", "Spring Boot Application/1.0");
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

            SecondLoginRequest secondLoginRequest = new SecondLoginRequest();
            secondLoginRequest.setMac(""); // Set MAC if available, else empty
            secondLoginRequest.setSignature(signature);
            secondLoginRequest.setUserName(userName);
            secondLoginRequest.setRandomKey(randomKey);
            secondLoginRequest.setPublicKey(""); // Per docs, can be empty
            secondLoginRequest.setEncryptType("MD5");
            secondLoginRequest.setIpAddress(clientIp);
            secondLoginRequest.setClientType(clientType);
            secondLoginRequest.setUserType("0"); // 0: System user
            secondLoginRequest.setSecretKey(base64SecretKey);
            secondLoginRequest.setSecretVector(base64SecretVector);

            HttpEntity<SecondLoginRequest> requestEntity = new HttpEntity<>(secondLoginRequest, headers);

            log.info("Initiating second login request to DSS at {} for user: {}", url, userName);
            log.info("Request body: {}", secondLoginRequest);

            ResponseEntity<SecondLoginResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    SecondLoginResponse.class
            );

            SecondLoginResponse response = responseEntity.getBody();
            // Optionally, store plainSecretKey and plainSecretVector for MQ decryption
            log.info("✅ Second login successful for user: {}. Status: {}", userName, responseEntity.getStatusCode());
            return response;

        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("❌ HTTP error during second login request to DSS for user: {}. Status: {}, Response: {}", userName, e.getStatusCode(), e.getResponseBodyAsString(), e);
            throw new DssServiceException("HTTP error during second login request to DSS: " + e.getStatusCode(), e);
        } catch (RestClientException ex) {
            log.error("❌ Error during second login request to DSS for user: {}. Exception: {}", userName, ex.getMessage(), ex);
            throw new DssServiceException("Error during second login request to DSS", ex);
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

            SecondLoginResponse secondLoginResponse = secondLogin();
            String token = secondLoginResponse.getToken();

            if (token == null) {
                log.error("❌ Failed to get token from DSS");
                throw new DssServiceException("Failed to get token from DSS", null);
            }

            String url = baseUrl + "/brms/api/v1.0/BRM/Config/GetMqConfig";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-Subject-Token", token);

            HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

            ResponseEntity<GetMqConfigResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    GetMqConfigResponse.class
            );
            return responseEntity.getBody();
        } catch (RestClientException e) {
            log.error("Error getting MQ config", e);
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
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int idx = (int) (Math.random() * chars.length());
            sb.append(chars.charAt(idx));
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
