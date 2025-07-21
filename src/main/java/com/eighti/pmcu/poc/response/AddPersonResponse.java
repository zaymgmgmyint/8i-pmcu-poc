package com.eighti.pmcu.poc.response;

import lombok.Data;
import java.util.List;

/**
 * Minimal AddPersonResponse for POST /obms/api/v1.1/acs/person
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
