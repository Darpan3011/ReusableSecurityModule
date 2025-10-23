package com.darpan.starter.security.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

@Validated
@ConfigurationProperties(prefix = "security")
@Data
public class SecurityProperties {

    private Cors cors = new Cors();
    private List<String> publicEndpoints = new ArrayList<>();
    private boolean csrfEnabled = false;

    // toggles
    private boolean oauth2Enabled = false;
    private boolean jwtEnabled = true;

    // jwt specific
    private String jwtSecret = "ReplaceWithStrongSecretAtLeast32CharsLong____";
    private long jwtExpirationSeconds = 3600;
    private long refreshTokenExpirationSeconds = 86400;

    // oauth2 redirect
    private String oauth2SuccessRedirectUrl = "http://localhost:3000/";

    @Data
    public static class Cors {
        private boolean enabled = true;
        private String allowedOrigins = "http://localhost:3000";
        private String allowedMethods = "*";
        private String allowedHeaders = "*";
        private String exposedHeaders = "*";
        private boolean allowCredentials = true;
        private long maxAge = 3600;
    }
}
