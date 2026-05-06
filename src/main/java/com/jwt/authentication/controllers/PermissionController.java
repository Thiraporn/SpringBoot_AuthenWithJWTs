package com.jwt.authentication.controllers;

import com.jwt.authentication.models.Permission;
import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.response.MenuResponse;
import com.jwt.authentication.services.MenuService;
import com.jwt.authentication.services.PermissionService;
import com.jwt.authentication.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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
//    @GetMapping("/get-permissions")
//    public List<String> getPermissions(Authentication auth) {
//        List<Permission> permissions  = permissionService.getAuthorizedPermission(auth);
//        return permissions.stream()
//                .map(Permission::getMenuCode)
//                .distinct()
//                .toList();
//    }
    @GetMapping("/get-permissions")
    public ResponseEntity<List<MenuResponse>> getMenusByUserAuthorized(Authentication auth) {
        List<MenuResponse> menuResponse  = permissionService.getMenusByUserAuthorized(auth);
        System.out.println("getMenusByUserAuthorized>>> "+menuResponse.toString());
        return ResponseEntity.ok(menuResponse);
    }



}
