package com.jwt.authentication.services;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import com.jwt.authentication.models.User;
import com.jwt.authentication.configuration.CookieProperties;
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
public class JwtTokenService {// tool  ในการช่วยตรวจสอบการเข้ามาใช้งานระบบ

    @Value("${jwt.expiration.ms}")
    private int jwtExpirationMs;//เวลาหมดอายุของ JWT (มิลลิวินาที)

    @Value("${jwt.refresh.expiration.ms}")
    private int jwtRefreshExpirationMs;//เวลาหมดอายุของ Refresh JWT (มิลลิวินาที)

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
        catch (JwtException | IllegalArgumentException e) {
            return false; // ไม่ต้อง log ซ้ำ
        }
    }
}
