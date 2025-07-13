package com.eighti.pmcu.poc.service;

import com.eighti.pmcu.poc.request.AddPersonRequest;
import com.eighti.pmcu.poc.response.AddPersonResponse;
import com.eighti.pmcu.poc.exception.DssServiceException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * AGENT: Minimal PersonService for addPerson API integration
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PersonService {
    @Value("${dss.base-url}")
    private String baseUrl;

    private final RestTemplate restTemplate;
    private final DssService dssService;

    public AddPersonResponse addPerson(AddPersonRequest req) {
        // AGENT: Use the actual DSS session token for API calls
        String token = dssService.getCurrentToken();
        if (token == null) {
            log.error("❌ No DSS token available for addPerson");
            throw new DssServiceException("No DSS token available for addPerson", null);
        }
        String url = baseUrl + "/obms/api/v1.1/acs/person";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Subject-Token", token);
        HttpEntity<AddPersonRequest> requestEntity = new HttpEntity<>(req, headers);
        try {
            ResponseEntity<AddPersonResponse> responseEntity = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    AddPersonResponse.class
            );
            AddPersonResponse response = responseEntity.getBody();
            if (responseEntity.getStatusCode().is2xxSuccessful() && response != null && response.getCode() == 1000) {
                log.info("✅ addPerson successful. Response: {}", response);
                return response;
            } else {
                log.error("❌ addPerson failed. Status: {}, Response: {}", responseEntity.getStatusCode(), response);
                throw new DssServiceException("addPerson failed: " + responseEntity.getStatusCode(), null);
            }
        } catch (RestClientException e) {
            log.error("❌ Error calling addPerson API: {}", e.getMessage(), e);
            throw new DssServiceException("Error calling addPerson API", e);
        }
    }

    // AGENT: Expose the current DSS session token from DssService
    // (Add this method to DssService.java)
    // public String getCurrentToken() {
    //     return currentToken.get();
    // }
}
