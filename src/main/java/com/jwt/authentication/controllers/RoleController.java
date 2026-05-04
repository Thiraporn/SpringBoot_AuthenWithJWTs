package com.jwt.authentication.controllers;

import com.jwt.authentication.models.Role;
import com.jwt.authentication.services.RoleService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @GetMapping("/all-roles")
    public ResponseEntity<?> getRoles(HttpServletRequest request) {
        List<Role> roles = roleService.getAllRoles() ;
        return ResponseEntity.ok(roles);
    }



}
