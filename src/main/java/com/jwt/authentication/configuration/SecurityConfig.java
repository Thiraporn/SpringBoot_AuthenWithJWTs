package com.jwt.authentication.configuration;

import com.jwt.authentication.logger.LoggingFilter;
import com.jwt.authentication.security.jwt.AuthEntryPointJwt;
import com.jwt.authentication.security.jwt.AuthTokenFilter;
import com.jwt.authentication.security.services.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity//เปิดใช้ระบบ Spring Security
@RequiredArgsConstructor
public class SecurityConfig {//Rules ของระบบรักษาความปลอดภัย โดย implement Spring Security

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;// บอกว่าถ้าใครไม่ได้รับอนุญาตจะทำอะไร

    @Autowired
    UserDetailsServiceImpl userDetailsService;//โหลดข้อมูล user จากระบบ

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {//สร้างตัวกรอง JWT → จะตรวจสอบทุกคำขอ
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {//Spring จะใช้ AuthenticationManager ตรวจสอบผู้ใช้
        return authConfig.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {//ใช้ BCrypt เข้ารหัสรหัสผ่าน → ปลอดภัย ถ้าใครแอบดูฐานข้อมูลก็อ่านรหัสผ่านไม่ได้
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {//“เวลาตรวจสอบผู้ใช้ ให้โหลดข้อมูลจาก userDetailsService และเข้ารหัสรหัสผ่านด้วย BCrypt”
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    //กำหนดการเข้าถึงข้ามโดเมน (CORS) → สำหรับกรณี frontend กับ backend อยู่คนละที่
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                //ปิด CSRF → ไม่ใช้ token ของ Spring สำหรับฟอร์ม (เพราะใช้ JWT ที่ custom เองแทนแล้ว)
                .csrf(csrf -> csrf.disable())
                //ตั้งค่า CORS → อนุญาตให้ frontend จากโดเมนอื่นเข้าถึง API
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                //ตั้งค่า exceptionHandling → ใช้ unauthorizedHandler เมื่อเข้าถึงไม่ได้
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                //ตั้งค่า sessionManagement → STATLESS → ไม่มี session เก็บบน server ใช้ JWT แทน
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // ตั้งค่า สิทธิ์เข้าถึง  /register, /test-register, /login → ทุกคนเข้าถึงได้   ทุก request อื่น ๆ → ต้องล็อกอิน
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register","/test-register", "/authen","/refreshtoken").permitAll()
                        .anyRequest().authenticated()
                );
                //เพิ่ม LoggingFilter → บันทึกทุก request
                http.addFilterBefore(new LoggingFilter(), UsernamePasswordAuthenticationFilter.class);
                //ตั้งค่า AuthenticationProvider → ตรวจสอบผู้ใช้และรหัสผ่าน
                http.authenticationProvider(authenticationProvider() );
                //เพิ่ม JWT Filter → ตรวจสอบ JWT ก่อนเข้าถึงระบบ
                http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        //สร้าง filter chain → ระบบ security ทำงานตามที่เรากำหนด   ---> วิ่งไปที่นี่ AuthTokenFilter ------>  เสร็จแล้ว ถ้า JWT ผิด → ปฏิเสธทันที → ไปเจอAuthEntryPointJwt
        return http.build();
    }
}