package com.jwt.authentication.controllers;

import com.jwt.authentication.models.Permission;
import com.jwt.authentication.services.PermissionService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping("/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @GetMapping("/all-permissions")
    public ResponseEntity<?> getPermission(HttpServletRequest request) {
        List<Permission> permissions = permissionService.getAllPermissions() ;
        return ResponseEntity.ok(permissions);
    }
    @PostMapping("/save-permission")
    public ResponseEntity<?> savePermission(@RequestBody List<Permission> permissions) {
        permissionService.doPermissions(permissions);
        return ResponseEntity.ok("permissions saved");
    }



}
