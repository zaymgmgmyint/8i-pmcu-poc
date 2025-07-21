package com.eighti.pmcu.poc.request;

import lombok.Data;

/**
 * Minimal AddPersonRequest for POST /obms/api/v1.1/acs/person
 */
@Data
public class AddPersonRequest {
    private BaseInfo baseInfo;
    private ExtensionInfo extensionInfo;
    private AuthenticationInfo authenticationInfo;
    private AccessInfo accessInfo;
    private FaceComparisonInfo faceComparisonInfo;

    @Data
    public static class BaseInfo {
        private String personId;
        private String firstName;
        private String gender;
        private String orgCode;
    }

    @Data
    public static class ExtensionInfo {
        private String idType;
        private String nationalityId;
    }

    @Data
    public static class AuthenticationInfo {
        private String startTime;
        private String endTime;
    }

    @Data
    public static class AccessInfo {
        private String accessType;
    }

    @Data
    public static class FaceComparisonInfo {
        private String enableFaceComparisonGroup;
    }
}
