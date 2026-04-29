package com.jwt.authentication.controllers;


import com.jwt.authentication.models.Menu;
import com.jwt.authentication.services.MenuService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;


@RestController
@RequestMapping("/menus")
@RequiredArgsConstructor
public class MenuController {

    private final MenuService menuService;

    @PostMapping("/menus-all")
    public ResponseEntity<?> getMenusList(HttpServletRequest request) {
        List<Menu> orders = menuService.getAllMenus();
        return ResponseEntity.ok(orders);
    }

    @PostMapping("/save")
    public ResponseEntity<?> saveMenu(@RequestBody Menu menu) {
        return ResponseEntity.ok(menuService.doSaveMenu(menu));
    }

    @PostMapping("/count")
    public ResponseEntity<?> saveMenu(HttpServletRequest request) {
        List<Menu> orders = menuService.getAllMenus();
        return ResponseEntity.ok(orders.size());
    }


}
