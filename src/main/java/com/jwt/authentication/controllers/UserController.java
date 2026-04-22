package com.jwt.authentication.controllers;

import com.jwt.authentication.models.User;
import com.jwt.authentication.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;


@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/users")
    public ResponseEntity<?> getUsers(HttpServletRequest request) {
        List<User> orders = userService.getAllUsers() ;
        return ResponseEntity.ok(orders);
    }

}
