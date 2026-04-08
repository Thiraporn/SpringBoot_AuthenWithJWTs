package com.jwt.authentication.security.jwt;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import com.jwt.authentication.security.services.UserDetailsImpl;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Slf4j
@Component
public class JwtUtils {// tool  ในการช่วยตรวจสอบการเข้ามาใช้งานระบบ

    @Value("${jwt.expiration.ms}")
    private int jwtExpirationMs;//เวลาหมดอายุของ JWT (มิลลิวินาที)

    //รหัสลับสำหรับสร้าง JWT (ต้องเก็บให้ปลอดภัย)
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public JwtUtils(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    //ตัวสร้าง JWT สำหรับ user 1 คน  //สุดท้าย return สตริง JWT ที่ user จะเก็บไว้
    public String generateAccessToken(Authentication authentication) {
        //ขั้นตอน:
        //1.ดึงข้อมูล  user จาก Authentication
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
//                .claim("roles", userPrincipal.getAuthorities().stream()
//                                   .map(item -> item.getAuthority())
//                                   .collect(Collectors.toList()))
                .setIssuedAt(new Date())
                //2.กำหนด วันออกบัตร และ วันหมดอายุ
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                //3.เซ็นด้วย รหัสลับ (key) เพื่อให้ JWT ปลอดภัย
                //.signWith(key(), SignatureAlgorithm.HS256)
                .signWith(privateKey, SignatureAlgorithm.RS256)//generate token (ใช้ private key เท่านั้น)
                .compact();
    }
    //แปลง รหัสลับ (jwtSecret) เป็น Key ที่ใช้เซ็น JWT
//    private Key key() {
//        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
//    }
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

}
