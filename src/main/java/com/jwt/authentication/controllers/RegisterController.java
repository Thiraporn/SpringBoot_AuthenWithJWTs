package com.jwt.authentication.controllers;

import com.jwt.authentication.payload.request.SignupRequest;
import com.jwt.authentication.payload.response.MessageResponse;
import com.jwt.authentication.services.RegisterService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
public class RegisterController {
    private final RegisterService registerService;

    // ตัวอย่าง GET เพื่อทดสอบ
    @GetMapping("/test-register")
    public ResponseEntity<?> showRegisterPage() {
        return ResponseEntity.ok(new MessageResponse("This is the register page"));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        MessageResponse messageResponse = registerService.register(signUpRequest);
        return ResponseEntity.ok(messageResponse);
    }
}
