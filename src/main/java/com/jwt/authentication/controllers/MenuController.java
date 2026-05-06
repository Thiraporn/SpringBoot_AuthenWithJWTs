package com.jwt.authentication.controllers;


import com.jwt.authentication.models.Menu;
import com.jwt.authentication.services.MenuService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    @GetMapping("/autocomplete/search")
    public ResponseEntity<List<Menu>> searchAutocompleteParentMenus( @RequestParam String q  ) {
        List<Menu> result = menuService.searchAutocompleteParentMenus(q);
        return ResponseEntity.ok(result);
    }
    @GetMapping("/datatable/{code}/submenus")
    public ResponseEntity<List<Menu>> getDatableSubMenusByParentCode(@PathVariable String code) {
        List<Menu> result =  menuService.getDatableSubMenusByParentCode(code);
        return ResponseEntity.ok(result);
    }


}
