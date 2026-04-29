package com.jwt.authentication.controllers;

import com.ana.common.security.libs.payload.MessageResponse;
import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.request.SignupRequest;
import com.jwt.authentication.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;


@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/all-users")
    public ResponseEntity<?> getUsers(HttpServletRequest request) {
        List<User> orders = userService.getAllUsers() ;
        return ResponseEntity.ok(orders);
    }

    @PostMapping("/save-user")
    public ResponseEntity<?> registerUser(@Valid @RequestBody User user) {
        return ResponseEntity.ok( userService.doSaveUser(user));
    }

}
