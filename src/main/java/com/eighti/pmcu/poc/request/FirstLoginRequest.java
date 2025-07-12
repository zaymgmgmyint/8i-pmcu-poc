package com.eighti.pmcu.poc.request;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class FirstLoginRequest {

    private String userName;

    private String ipAddress;

    private String clientType;
}