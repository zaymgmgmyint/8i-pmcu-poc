package com.eighti.pmcu.poc.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**") // Apply CORS to paths starting with /api/
                .allowedOrigins("*") // Change to specific origins in production
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Specify allowed HTTP methods
                .allowedHeaders("*") // Allow all headers
                .allowCredentials(false) // Disable credentials (cookies, auth tokens, etc.)
                .maxAge(3600); // Maximum age for CORS pre-flight request cache in seconds
    }
}

