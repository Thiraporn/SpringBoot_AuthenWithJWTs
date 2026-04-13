package com.jwt.authentication.security.jwt;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
@Data
@Component
@ConfigurationProperties(prefix = "jwt.cookie")
public class JwtCookieProperties {
    private String accessTokenName;
    private String refreshTokenName;
    private String path;
    private boolean httpOnly;
    private boolean secure;
    private String sameSite;
    private long maxAge;
}