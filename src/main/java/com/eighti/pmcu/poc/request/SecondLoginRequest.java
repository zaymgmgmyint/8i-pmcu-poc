package com.eighti.pmcu.poc.request;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SecondLoginRequest {

    private String mac;

    private String signature;

    private String userName;

    private String password;

    private String randomKey;

    private String publicKey;

    private String encryptType;

    private String ipAddress;

    private String clientType;

    private String userType;

    private String secretKey;

    private String secretVector;

    private String authorityType;
}
