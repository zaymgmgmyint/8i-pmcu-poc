package com.eighti.pmcu.poc.response;

import lombok.Data;
import java.util.List;

// DTO for vms.addVisitor MQ message, aligned with AddVisitorRequest and using Lombok
@Data
public class VmsAddVisitorMessage {
    private String method;
    private Info info;
    private String email;
    private String expectArrivalTime;
    private String arrivalTime;
    private String expectLeaveTime;
    private String leaveTime;
    private String plateNo;
    private String reason;
    private String remark;
    private String personId;
    private AuthInfo authInfo;
    private String id;

    @Data
    public static class Info {
        private String visitorId;
        private String status;
        private String source;
        private String registerType;
        private String registerDetail;
        private String createTime;
        private String visitorName;
        private String visitorOrgName;
        private String visitedName;
        private String visitedOrgName;
        private String idType;
        private String idNum;
        private String tel;
    }

    @Data
    public static class AuthInfo {
        private String sipId;
        private String cardNo;
        private List<String> facePictures;
        private String passportCardNo;
        private String idPicture;
        private String qrcode;
        private RightInfo rightInfo;
    }

    @Data
    public static class RightInfo {
        private List<String> acsChannelIds;
        private List<String> vtoChannelIds;
        private List<String> positionIds;
        private List<LiftChannel> liftChannels;
    }

    @Data
    public static class LiftChannel {
        private String channelId;
        private String floors;
    }
}
