package com.jwt.authentication.controllers;

import com.ana.common.security.libs.payload.MessageResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/authentication-service")
public class HealthCheckController {
    // ตัวอย่าง GET เพื่อทดสอบ
    @GetMapping("/healthcheck")
    public ResponseEntity<?> showRegisterPage() {
        return ResponseEntity.ok(new MessageResponse("This is the health-check page : authentication-service"));
    }

}
