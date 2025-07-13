package com.eighti.pmcu.poc.response;

import lombok.Data;
import java.util.List;

/**
 * AGENT: Minimal AddPersonResponse for POST /obms/api/v1.1/acs/person
 * Only required fields and nested classes included for POC.
 */
@Data
public class AddPersonResponse {
    private int code;
    private String desc;
    private DataDto data;

    @Data
    public static class DataDto {
        private List<String> existPlateNos;
        private List<String> existCardNos;
        private List<String> overstepPlateNos;
    }
}

