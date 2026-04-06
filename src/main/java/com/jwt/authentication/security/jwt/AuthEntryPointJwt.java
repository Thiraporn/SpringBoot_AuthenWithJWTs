package com.jwt.authentication.security.jwt;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Slf4j
@Component //บอกให้ Spring รู้จักคลาสนี้เป็น “ส่วนประกอบ” ของระบบ สามารถเรียกใช้โดยอัตโนมัติ
public class AuthEntryPointJwt  implements AuthenticationEntryPoint { //จุดเริ่มต้นสำหรับการตรวจสอบการเข้าสู่ระบบ (Entry point) คือจะถูกเรียกทันที เมื่อใครสักคนเข้ามาโดยไม่ได้ล็อกอินหรือไม่มีสิทธิ์
    //commence เมธอดนี้คือสิ่งที่จะทำงาน เมื่อมีคนเข้าถึงโดยไม่ได้รับอนุญาต

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        log.error("Unauthorized error: {}", authException.getMessage(), authException);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");//HTTP 401 Error: Unauthorized
    }

}
