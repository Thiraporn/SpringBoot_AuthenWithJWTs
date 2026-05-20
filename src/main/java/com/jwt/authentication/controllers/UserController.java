package com.jwt.authentication.controllers;

import com.ana.common.security.libs.payload.MessageResponse;
import com.jwt.authentication.models.Menu;
import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.request.SignupRequest;
import com.jwt.authentication.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<?> saveUser(@Valid @RequestBody User user) {
        return ResponseEntity.ok( userService.doSaveUser(user));
    }

    @PutMapping("/edit/{id}")
    public ResponseEntity<?> updateUser(@Valid @RequestBody User user) {
        return ResponseEntity.ok( userService.updateUser(user));
    }

    @GetMapping("/autocomplete/search")
    public ResponseEntity<List<User>> searchAutocompleteUsers(@RequestParam String q  ) {
        List<User> result = userService.searchAutocompleteUsers(q);
        return ResponseEntity.ok(result);
    }

}
