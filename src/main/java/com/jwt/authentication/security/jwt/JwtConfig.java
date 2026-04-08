package com.jwt.authentication.security.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PrivateKey;
import java.security.PublicKey;

@Configuration
public class JwtConfig {

    @Value("${jwt.privateKeyPath}")
    private String privateKeyPath;

    @Value("${jwt.publicKeyPath}")
    private String publicKeyPath;

    @Bean
    public PrivateKey privateKey() throws Exception {
        return KeyUtils.loadPrivateKey(privateKeyPath);
    }

    @Bean
    public PublicKey publicKey() throws Exception {
        return KeyUtils.loadPublicKey(publicKeyPath);
    }

}