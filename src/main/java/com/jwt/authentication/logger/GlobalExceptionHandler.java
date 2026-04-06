package com.jwt.authentication.logger;

import com.jwt.authentication.payload.response.ErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.nio.file.AccessDeniedException;
import java.security.SignatureException;
import java.time.Instant;

/*ทุกครั้งที่เกิด Exception (ข้อผิดพลาด) ในระบบ  จะถูกจับที่นี่ก่อน บันทึก log*/
@Slf4j
@RestControllerAdvice //บอก Spring ว่า นี่คือ handler สำหรับ exception ทั้งระบบ
public class GlobalExceptionHandler {
    // จับ Exception ทั่วไป
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAllExceptions(Exception ex) {
        //บันทึก ข้อความ error + stack trace ลง log
        log.error("GLOBAL ERROR: {}", ex.getMessage(), ex);
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong");
    }

    // จับข้อผิดพลาดเกี่ยวกับ Authentication
    @ExceptionHandler({BadCredentialsException.class})
    public ResponseEntity<ErrorResponse> handleBadCredentials(BadCredentialsException ex) {
        log.error("AUTH ERROR: {}", ex.getMessage(), ex);
        return buildResponse(HttpStatus.UNAUTHORIZED, "Invalid username or password");
    }

    // จับข้อผิดพลาดเมื่อเข้าถึง resource ที่ไม่ได้รับอนุญาต
    @ExceptionHandler({AccessDeniedException.class})
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        log.error("ACCESS DENIED: {}", ex.getMessage(), ex);
        return buildResponse(HttpStatus.FORBIDDEN, "You do not have permission to access this resource");
    }

    // จับข้อผิดพลาดจาก Validation
    @ExceptionHandler({ConstraintViolationException.class})
    public ResponseEntity<ErrorResponse> handleValidationException(ConstraintViolationException ex) {
        log.error("VALIDATION ERROR: {}", ex.getMessage(), ex);
        return buildResponse(HttpStatus.BAD_REQUEST, "Validation failed: " + ex.getMessage());
    }

    // จับ JWT Exceptions
    @ExceptionHandler({
            ExpiredJwtException.class,
            MalformedJwtException.class,
            UnsupportedJwtException.class,
            IllegalArgumentException.class,
            SignatureException.class
    })
    public ResponseEntity<ErrorResponse> handleJwtException(Exception ex) {
        log.error("JWT ERROR: {}", ex.getMessage(), ex);
        String message;
        if (ex instanceof ExpiredJwtException) message = "JWT token is expired";
        else if (ex instanceof MalformedJwtException) message = "Invalid JWT token";
        else if (ex instanceof UnsupportedJwtException) message = "Unsupported JWT token";
        else if (ex instanceof SignatureException) message = "Invalid JWT signature";
        else message = "JWT error";

        return buildResponse(HttpStatus.UNAUTHORIZED, message);
    }


    // สร้าง Response ใช้ model ErrorResponse ของคุณ
    private ResponseEntity<ErrorResponse> buildResponse(HttpStatus status, String message) {
        ErrorResponse error = ErrorResponse.builder()
                .status(status.value())
                .message(message)
                .timestamp(Instant.now().toEpochMilli())
                .build();

        return ResponseEntity.status(status).body(error);
    }


}