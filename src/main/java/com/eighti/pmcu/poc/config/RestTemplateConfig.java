// Updated RestTemplateConfig.java with SSL bypass and 401 error handler
package com.eighti.pmcu.poc.config;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate() {
        try {
            // Create SSL context that trusts all certificates
            SSLContext sslContext = SSLContextBuilder.create()
                    .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                    .build();

            // Configure SSL socket factory to skip hostname verification
            SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create()
                    .setSslContext(sslContext)
                    .setHostnameVerifier((hostname, session) -> true) // Skip hostname verification
                    .build();

            // Build HTTP client with custom SSL configuration
            HttpClient httpClient = HttpClientBuilder.create()
                    .setConnectionManager(
                            PoolingHttpClientConnectionManagerBuilder.create()
                                    .setSSLSocketFactory(sslSocketFactory)
                                    .build())
                    .build();

            // Create RestTemplate with custom HTTP client and error handler
            HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
            RestTemplate restTemplate = new RestTemplate(factory);

            // Custom error handler allows 401 responses through for challenge payload
            restTemplate.setErrorHandler(new ResponseErrorHandler() {
                @Override
                public boolean hasError(ClientHttpResponse response) throws IOException {
                    return response.getStatusCode().isError() &&
                            response.getStatusCode().value() != HttpStatus.UNAUTHORIZED.value();
                }

                @Override
                public void handleError(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
                    throw new IOException("HTTP error: " + response.getStatusCode() + " for " + method + " " + url);
                }
            });

            return restTemplate;

        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSL-configured RestTemplate", e);
        }
    }
}