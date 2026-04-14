package com.jwt.authentication.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
@Data
@Component
@ConfigurationProperties(prefix = "jwt.cookie")
public class CookieProperties {
    private String accessTokenName;
    private String refreshTokenName;
    private String path;
    private boolean httpOnly;
    private boolean secure;
    private String sameSite;
    private long maxAge;
}