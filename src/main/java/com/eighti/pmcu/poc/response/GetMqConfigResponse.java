package com.eighti.pmcu.poc.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GetMqConfigResponse {
    @Schema(description = "Error code", example = "1000")
    private int code;
    @Schema(description = "Result description", example = "Success")
    private String desc;
    @Schema(description = "MQ configuration data")
    private DataDto data;

    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class DataDto {
        @Schema(description = "Whether to enable TLS: 0=No; 1=Yes", example = "1")
        private String enableTls;
        @Schema(description = "MQ username", example = "consumer")
        private String userName;
        @Schema(description = "MQTT protocol address", example = "192.168.1.1:1883")
        private String mqtt;
        @Schema(description = "AMQP protocol address", example = "192.168.1.1:5672")
        private String amqp;
        @Schema(description = "STOMP protocol address", example = "192.168.1.1:61613")
        private String stomp;
        @Schema(description = "WSS protocol address", example = "192.168.1.1:61615")
        @JsonProperty("wss")
        private String wss;
        @Schema(description = "Openwire protocol address (PC)", example = "192.168.1.1:61616")
        private String addr;
        @Schema(description = "Encrypted MQ password (AES)", example = "b48891f8dd49d3d8e3138763a1505aaf353479dd5ecdb9d72a52a99b12a29d88")
        @JsonProperty(value = "password")
        private String password;
    }
}