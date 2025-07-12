package com.eighti.pmcu.poc.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class FirstLoginResponse {
    @Schema(description = "Encrypted field. Used to generate a signature for the second login.", example = "f689ed8c40030d68007d6e95002f7f87")
    private String realm;

    @Schema(description = "Random secret key. Can be used as a parameter for the second login and will take effect after 10 seconds.", example = "48c008d0026a49c4")
    private String randomKey;

    @Schema(description = "Encryption mode. Can be used as a parameter for the second login.", example = "MD5")
    private String encryptType;

    @Schema(description = "Platform RSA-encrypted public key, base64 coded. Can be used to encrypt the secret key and AES vector.", example = "MIGf000GCS...iH+FFwu9wID00AB")
    private String publicKey;
}
