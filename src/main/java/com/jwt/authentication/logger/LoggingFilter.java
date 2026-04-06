package com.jwt.authentication.logger;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;

@Slf4j
@Component //บอก Spring ให้รู้จัก filter ตัวนี้
public class LoggingFilter  implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        //แปลง request/response ให้เป็น HTTP
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        //เก็บเวลาตอนเริ่ม → ใช้วัดว่า request นี้ใช้เวลานานเท่าไร
        long start = System.currentTimeMillis();

        try {
            //บันทึก ทุก header ที่ส่งมา
            Collections.list(req.getHeaderNames())
                    .forEach(header ->
                            log.debug("Header: {}={}", header, req.getHeader(header))
                    );
            //บันทึก Method + URL
            // Request
            log.debug("{} {}", req.getMethod(), req.getRequestURI());

            //ส่ง request ต่อไปยัง ระบบหลังบ้าน / filter ตัวต่อไป
            chain.doFilter(request, response);

        } catch (Exception ex) {
            //ถ้ามี error เกิดขึ้น → บันทึก error พร้อม Method + URL + ข้อความ
            //  Error log
            log.error("ERROR {} {} - {}",
                    req.getMethod(),
                    req.getRequestURI(),
                    ex.getMessage(),
                    ex
            );
            //จากนั้น โยน error ต่อไป ให้ Spring จัดการต่อ
            throw ex; // ต้อง throw ต่อให้ Spring handle
        }
        //วัดเวลาที่ request ใช้ทั้งหมด
        long duration = System.currentTimeMillis() - start;
        //บันทึก status code + URL + เวลาใช้ (ms)
        //  Response
        log.debug("{} {} {}ms",
                res.getStatus(),
                req.getRequestURI(),
                duration);
    }
}
