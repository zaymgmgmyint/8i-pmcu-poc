package com.eighti.pmcu.poc.controller;

import com.eighti.pmcu.poc.response.FirstLoginResponse;
import com.eighti.pmcu.poc.response.GetMqConfigResponse;
import com.eighti.pmcu.poc.response.SecondLoginResponse;
import com.eighti.pmcu.poc.service.DssService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * AGENT: See: docs/dss-api-spec.md
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class DssAuthController {
    private final DssService dssService;

    @GetMapping("/first-login")
    public FirstLoginResponse getFirstLogin() {
        log.info("Received request for DSS first login info");
        return dssService.firstLogin();
    }

    @GetMapping("/second-login")
    public SecondLoginResponse getSecondLogin() {
        log.info("Received request for DSS second login");
        return dssService.secondLogin1();
    }

    @GetMapping("/mq-config")
    public GetMqConfigResponse getMqConfig() {
        log.info("Received request for DSS MQ config");
        return dssService.getMqConfig();
    }
}
