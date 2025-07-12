package com.eighti.pmcu.poc.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class SecondLoginResponse {
    @Schema(description = "Keep-alive interval (seconds). The [3.1.3 Heartbeat Keep-alive] interface needs to be called within this time.", example = "30")
    private Integer duration;

    @Schema(description = "Used for interface authentication. For usage, see [5.1 Login Authentication].", example = "a15ee202efab4a54af01c5c0a4ed9bac")
    private String token;

    @Schema(description = "Session credentials for downloading static resources such as images and files. For usage, see [2.3 图片访问规定].", example = "ff435202efab4a54af01c5c0a4e65abe")
    private String credential;

    @Schema(description = "User ID.", example = "1")
    private String userId;

    @Schema(description = "User group ID.", example = "1")
    private String userGroupId;

    @Schema(description = "Session credential used to reset the password for first login; valid once and lasts 5 minutes.", example = "69607e74f...03f1ef")
    private String verification;

    @Schema(description = "Service ability (reserved field, may be null)")
    private Object serviceAbilty;

    @Schema(description = "Version information.")
    private VersionInfo versionInfo;

    @Schema(description = "E-map path (deprecated, may be null)")
    private String emapUrl;

    @Schema(description = "Calling number, for video intercom service.", example = "8888881000")
    private String sipNum;

    @Schema(description = "SIP password, encrypted with terminal public key, for video intercom service.", example = "4CFC...EE8")
    private String sipPassword;

    @Schema(description = "Cluster intercom registration number.", example = "6666661000")
    private String pocId;

    @Schema(description = "The cluster intercom registers the password and uses the terminal public key for encryption.", example = "3ABF3...B78")
    private String pocPassword;

    @Schema(description = "Session token update frequency (seconds). The [3.1.4 Update Token] interface needs to be called within this time.", example = "1800")
    private Integer tokenRate;

    @Schema(description = "Reused or not: 0=No, 1=Yes.", example = "1")
    private String reused;

    @Schema(description = "User level: 1=Super administrator; 2=Administrator; 3=Custom role.", example = "1")
    private String userLevel;

    @Schema(description = "ID of the person bound to the app.", example = "1000001")
    private String personId;

    @Schema(description = "Whether the personnel is the owner, APP judges whether the personnel management is displayed.", example = "1")
    private Integer houseHolder;

    @Schema(description = "Forcibly modify password.", example = "0")
    private Integer forceResetPassword;

    @Schema(description = "Login UTC time.", example = "1726127578")
    private Long loginDateUtc;

    @Schema(description = "Enable password validity verification: 0=No, 1=Yes.", example = "1")
    private String enablePasswordValidityPeriod;

    @Schema(description = "The remaining validity period of the user's current password, in days.", example = "90")
    private String passwordRemainValidityPeriod;

    @Schema(description = "Has the IP of the current login changed from the previous login: 0=No, 1=Yes.", example = "0")
    private String loginIpChanged;

    @Schema(description = "The IP address of the current user’s last login.", example = "192.168.1.100")
    private String lastLoginIp;

    @Schema(description = "Ciphertext of secret key = RSA encryption (secret key, public key of terminal). Compatible with previous versions, when the publicKey parameter is empty, this field also returns empty.", example = "iYBQqQBCoq...N84A==")
    private String secretKey;

    @Schema(description = "Vector ciphertext = RSA encryption (vector, public key of terminal). Compatible with previous versions, when the publicKey parameter is empty, this field also returns empty.", example = "AblgO+BAVca3...eW3GFPg==")
    private String secretVector;

    @Data
    public static class VersionInfo {
        @Schema(description = "Latest version on client.", example = "1578852")
        private String lastVersion;
        @Schema(description = "Client update path.", example = "/client/x86/xxxxx1.exe;/client/x64/xxxxxx2.exe")
        private String updateUrl;
        @Schema(description = "Latest version on client patch.", example = "")
        private String patchVersion;
        @Schema(description = "Client patch update path.", example = "")
        private String patchUrl;
    }
}
