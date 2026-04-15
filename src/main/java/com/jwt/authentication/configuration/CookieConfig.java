package com.jwt.authentication.configuration;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

@Component
public class CookieConfig {

    @Autowired
    private CookieProperties cookieProps;

    //create cookie
    private ResponseCookie generateCookie(String name, String value, String path) {
        ResponseCookie cookie = ResponseCookie.from(name, value).path(path).maxAge(cookieProps.getMaxAge()).httpOnly(cookieProps.isHttpOnly())
                .secure(cookieProps.isSecure())
                .sameSite(cookieProps.getSameSite())
                .build();
        return cookie;
    }
    //set access token into cookie
    public ResponseCookie generateJwtCookie(String accessToken) {
        return generateCookie(cookieProps.getAccessTokenName(), accessToken, cookieProps.getPath());
    }
    //set  refresh token into cookie
    public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
        return generateCookie(cookieProps.getRefreshTokenName(), refreshToken, cookieProps.getPath());
    }
    //remove access token into cookie
    public ResponseCookie getCleanJwtCookie() {
        ResponseCookie cookie = ResponseCookie.from(cookieProps.getAccessTokenName(), null).path(cookieProps.getPath()).build();
        return cookie;
    }
    //remove refresh token into cookie
    public ResponseCookie getCleanJwtRefreshCookie() {
        ResponseCookie cookie = ResponseCookie.from(cookieProps.getRefreshTokenName(), null).path(cookieProps.getPath()).build();
        return cookie;
    }
    //cookie from http request
    public String getJwtRefreshFromCookies(HttpServletRequest request) {
        return getCookieValueByName(request, cookieProps.getRefreshTokenName());
    }

    //find cookie
    private String getCookieValueByName(HttpServletRequest request, String name) {
        Cookie cookie = WebUtils.getCookie(request, name);
        if (cookie != null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie c : cookies) {
                    System.out.println(c.getName() + " = " + c.getValue());
                }
            }
            return cookie.getValue();
        } else {
            return null;
        }
    }

}
