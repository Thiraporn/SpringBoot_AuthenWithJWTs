package com.jwt.authentication.services;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import com.jwt.authentication.models.User;
import com.jwt.authentication.security.jwt.JwtCookieProperties;
import com.jwt.authentication.security.services.UserDetailsImpl;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;


import io.jsonwebtoken.*;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

@Service
@Slf4j
//@Component
public class JwtTokenService {// tool  ในการช่วยตรวจสอบการเข้ามาใช้งานระบบ

    @Value("${jwt.expiration.ms}")
    private int jwtExpirationMs;//เวลาหมดอายุของ JWT (มิลลิวินาที)

    @Value("${jwt.refresh.expiration.ms}")
    private int jwtRefreshExpirationMs;//เวลาหมดอายุของ Refresh JWT (มิลลิวินาที)

    @Autowired
    private JwtCookieProperties cookieProps;

    //รหัสลับสำหรับสร้าง JWT (ต้องเก็บให้ปลอดภัย)
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public JwtTokenService(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String generateAccessToken(UserDetailsImpl userDetails) {
       return generateToken(userDetails,jwtExpirationMs);
    }
    public User generateRefreshToken(UserDetailsImpl userDetails) {
        long expiry = System.currentTimeMillis() + jwtRefreshExpirationMs;
        User user = new User();
        user.setUsername(userDetails.getUsername());
        user.setRefreshToken(generateToken(userDetails,jwtRefreshExpirationMs));
        user.setRefreshTokenExpiry(expiry);
       return user;
    }
    public String generateToken(UserDetailsImpl userDetails, int expirationMs) {
        return Jwts.builder()
                .setSubject((userDetails.getUsername()))
                .claim("roles", userDetails.getAuthorities().stream()
                                   .map(item -> item.getAuthority())
                                   .collect(Collectors.toList()))
                .setIssuedAt(new Date())
                //2.กำหนด วันออกบัตร และ วันหมดอายุ
                .setExpiration(new Date((new Date()).getTime() + expirationMs))
                //3.เซ็นด้วย รหัสลับ (key) เพื่อให้ JWT ปลอดภัย
                //.signWith(key(), SignatureAlgorithm.HS256)
                .signWith(privateKey, SignatureAlgorithm.RS256)//generate token (ใช้ private key เท่านั้น)
                .compact();
    }

    //อ่านชื่อผู้ใช้จาก JWT //ใช้ตอนตรวจสอบว่าใครเข้ามาใช้งาน
    public String getUserNameFromJwtToken(String token) {
        //อ่าน JWT → ดึง ชื่อผู้ใช้ ออกมา
        return Jwts.parserBuilder()
                //.setSigningKey(key())
                .setSigningKey(publicKey)// ใช้ public key
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }


    public List<String> getRolesFromJwt(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("roles", List.class);
    }
    //ตรวจสอบว่า JWT ถูกต้องหรือไม่  และยังไม่หมดอายุ
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    //.setSigningKey(key())
                    .setSigningKey(publicKey)// ใช้ public key
                    .build()
                    .parse(authToken);
            return true;
        }
       // หากไม่ถูกต้อง อาจมีข้อผิดพลาดที่ตรวจได้ เช่น:
        catch (MalformedJwtException e) {       //1.JWT ปลอม (MalformedJwtException)
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {       //2.JWT หมดอายุ (ExpiredJwtException)
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {   //3.JWT ไม่รองรับ (UnsupportedJwtException)
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {  //4.ไม่มีข้อมูล (IllegalArgumentException)
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
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
