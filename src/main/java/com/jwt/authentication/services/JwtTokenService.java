package com.jwt.authentication.services;
import java.security.PrivateKey;
import java.util.Date;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;


import io.jsonwebtoken.*;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class JwtTokenService {// tool  ในการช่วยตรวจสอบการเข้ามาใช้งานระบบ


    @Value("${jwt.expiration.ms}")
    private int jwtExpirationMs;//เวลาหมดอายุของ JWT (มิลลิวินาที)

    @Value("${jwt.refresh.expiration.ms}")
    private int jwtRefreshExpirationMs;//เวลาหมดอายุของ Refresh JWT (มิลลิวินาที)

    //รหัสลับสำหรับสร้าง JWT (ต้องเก็บให้ปลอดภัย)
    private final PrivateKey privateKey;
    //private final PublicKey publicKey;

    public JwtTokenService(PrivateKey privateKey ) {
        this.privateKey = privateKey;
        //this.publicKey = publicKey;
    }
    public String generateAccessToken(UserDetailsImpl userDetails) {
       return generateToken(userDetails,jwtExpirationMs);
    }
    public String generateRefreshToken(UserDetailsImpl userDetails) {
       return generateToken(userDetails,jwtRefreshExpirationMs);
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

}
