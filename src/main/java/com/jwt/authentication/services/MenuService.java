package com.jwt.authentication.services;

import com.jwt.authentication.models.Menu;
import com.jwt.authentication.repository.MenuRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;


@Slf4j
@Service
public class MenuService {
    @Autowired
    private MenuRepository menuRepository;

    public List<Menu> getAllMenus() {
        log.info("Getting all Menus from fact_orders");
        List<Menu> menus =  menuRepository.findAll();
        log.info("Total Menu: {}", menus.size());
        return menus;
    }
    public boolean doSaveMenu(Menu menu) {
        menuRepository.save(menu);
        log.info("Menu saved: {}", menu.getCode());
        return true;
    }






}
