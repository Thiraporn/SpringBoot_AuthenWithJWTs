package com.jwt.authentication.logger;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;

@Slf4j
@Component
public class LoggingFilter  implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        long start = System.currentTimeMillis();

        try {
            Collections.list(req.getHeaderNames())
                    .forEach(header ->
                            log.debug("Header: {}={}", header, req.getHeader(header))
                    );
            // 👉 Request
            log.debug("{} {}", req.getMethod(), req.getRequestURI());

            chain.doFilter(request, response);

        } catch (Exception ex) {
            // 👉 Error log (เหมือน Express next(err))
            log.error("ERROR {} {} - {}",
                    req.getMethod(),
                    req.getRequestURI(),
                    ex.getMessage(),
                    ex
            );
            throw ex; // ต้อง throw ต่อให้ Spring handle
        }

        long duration = System.currentTimeMillis() - start;

        // 👉 Response
        log.debug("{} {} {}ms",
                res.getStatus(),
                req.getRequestURI(),
                duration);
    }
}
