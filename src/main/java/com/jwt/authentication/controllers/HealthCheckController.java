package com.jwt.authentication.controllers;

import com.ana.common.security.libs.payload.MessageResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class HealthCheckController {
    @GetMapping("/")
    public String index() {
        return "index";
    }
    // ตัวอย่าง GET เพื่อทดสอบ
    @GetMapping("/healthcheck")
    public ResponseEntity<?> showRegisterPage() {
        return ResponseEntity.ok(new MessageResponse("This is the health-check page : authentication-service"));
    }


}
