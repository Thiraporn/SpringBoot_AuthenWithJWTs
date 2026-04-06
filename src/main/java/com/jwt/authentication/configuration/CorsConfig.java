package com.jwt.authentication.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "cors") //ดึงค่า allowedOrigins จากไฟล์ config
@Data
public class CorsConfig {//กฎสำหรับอนุญาตให้ frontend ที่อยู่คนละโดเมนเข้าถึง backend

    private List<String> allowedOrigins;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {//ประตู security อีกชั้น สำหรับ domain ต่างประเทศ หรือ ต่าง domain กัน เช่น React FrontEnd http://localhost:3000/employees    แต่ Authen ฺ์ฺBackEnd http://localhost:8080/auten

        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(allowedOrigins);//ใครเข้ามาได้บ้าง domain
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));//อนุญาต HTTP Method ไหนบ้าง (GET, POST, PUT, DELETE, OPTIONS)
        config.setAllowedHeaders(List.of("*"));//อนุญาต header ทุกชนิด (*)
        config.setAllowCredentials(true);//อนุญาตส่ง cookies หรือ credentials ข้ามโดเมน

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);//กฎนี้ใช้กับทุก URL ของ backend (/**)

        return source;
    }
}