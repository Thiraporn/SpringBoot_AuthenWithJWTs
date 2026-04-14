package com.jwt.authentication.security.jwt;
import java.io.IOException;

import com.jwt.authentication.security.services.UserDetailsServiceImpl;
import com.jwt.authentication.services.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

//ด่านตรวจเพื่อกรองการ Access เข้ามาในระบบ
// ซึ่งมี OncePerRequestFilter หมายความว่า ตัวกรองนี้จะทำงาน ครั้งเดียวต่อทุกคำขอ (request)
//สรุปสั้นๆ ==> ทุกครั้งที่คนเข้ามาที่เว็บ จะตรวจสอบ JWT ของ request
public class AuthTokenFilter  extends OncePerRequestFilter {
    //การตรวจสอบประกอบด้วย เครื่องมือ(tool) และ ตัวยืนยัน
    @Autowired
    private JwtTokenService jwtTokenService;//tool ในการตรวจสอบว่า JWT ถูกต้องไหม

    @Autowired
    private UserDetailsServiceImpl userDetailsService;//ตัวยืนยัน เครื่องมือตรวจสอบว่า ผู้ใช้นี้มีอยู่จริง และดึงข้อมูลผู้ใช้มา

    // main filter ทุกครั้งที่มีคนเข้ามา(request) มันจะถูกเรียกทันที
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);// ดึง JWT จากคำขอ (request)
            if (jwt != null && jwtTokenService.validateJwtToken(jwt)) {//ตรวจสอบว่า JWT มีและ ถูกต้อง
                String username = jwtTokenService.getUserNameFromJwtToken(jwt);//ถ้า JWT ถูกต้อง → ดึง ชื่อผู้ใช้ ออกมา

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);//ใช้ชื่อผู้ใช้เพื่อ โหลดข้อมูลผู้ใช้นั้น เช่น สิทธิ์การเข้าถึง
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());//สร้าง  instance ขึ้นมา → บอกระบบว่า “นี่คือผู้ใช้คนนี้ เขามีสิทธิ์แบบนี้”
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);//เก็บ user ที่ผ่าน authen เป็นที่เรียบร้อยไว้ใน SecurityContext → ระบบรู้ว่าใครเข้ามา และสามารถใช้สิทธิ์ตาม JWT ได้
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }
        //ส่งคำขอต่อไปยังระบบหลังบ้านได้
        //1 - ถ้า JWT ถูกต้อง → เข้าระบบได้
        //2 - ถ้า JWT ผิด → ระบบจะไม่ให้สิทธิ์ (เจอ AuthEntryPointJwt ด้านบน)
        filterChain.doFilter(request, response);
    }
    //ฟังก์ชันนี้ ดึง JWT จาก Header ของ HTTP
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        //Header ต้องเริ่มด้วย "Bearer " → ส่วนที่เหลือคือ JWT จริง ๆ
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }

        return null;
    }
}
