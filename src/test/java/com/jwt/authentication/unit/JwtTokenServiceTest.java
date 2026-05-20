package com.jwt.authentication.unit;

import com.jwt.authentication.models.ERole;
import com.jwt.authentication.services.JwtTokenService;
import com.jwt.authentication.services.UserDetailsImpl;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;


import org.junit.jupiter.api.BeforeEach;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.List;

class JwtTokenServiceTest {

    private JwtTokenService jwtTokenService;

    private PrivateKey privateKey;
    //read configuration
    @BeforeEach
    void setUp() throws Exception {
        // generate RSA key pair สำหรับ test
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        privateKey = pair.getPrivate();

        jwtTokenService = new JwtTokenService(privateKey);
    }
    //TEST CASE 1 : generateAccessToken : success
    @Test
    void generateAccessToken_shouldReturnToken() {
        UserDetailsImpl user = new UserDetailsImpl(
                "1",
                "springbootuser",
                "012347890",
                List.of(new SimpleGrantedAuthority(ERole.USER.name()))
        );

        String token = jwtTokenService.generateAccessToken(user);

        assertNotNull(token);
        assertTrue(token.startsWith("eyJ")); // JWT header base64
    }
    //TEST CASE 2 : generateRefreshToken : success
    @Test
    void generateRefreshToken_shouldReturnToken() {
        UserDetailsImpl user = new UserDetailsImpl(
                "1",
                "springbootuser",
                "012347890",
                //List.of(new SimpleGrantedAuthority("ROLE_" + ERole.USER.name()))
                List.of(new SimpleGrantedAuthority(ERole.USER.name()))
        );

        String token = jwtTokenService.generateRefreshToken(user);

        assertNotNull(token);
    }
}