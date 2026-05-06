package com.jwt.authentication.services;

import com.jwt.authentication.models.Menu;
import com.jwt.authentication.repository.MenuRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;


@Slf4j
@Service
public class MenuService {
    @Autowired
    private MenuRepository menuRepository;

    public List<Menu> getAllMenus() {
        log.info("Getting all Menus  ");
        List<Menu> menus =  menuRepository.findAll();
        log.info("Total Menu: {}", menus.size());
        return menus;
    }
    // generate new parent menu code
    public boolean doSaveMenu(Menu menu) {
        //long count = menuRepository.countByMenuParent("00");
        long count = menuRepository.countParentMenus();
        String nextCode = "P" + String.format("%04d", count + 1);
        menu.setCode(nextCode);
        menuRepository.save(menu);
        log.info("Parent Menu saved: {}", menu.getCode());

        return true;
    }
    // generate new sub menu code
    public boolean doSaveSubMenu(Menu menu) {
        //long count = menuRepository.countByMenuParentNot("00");
        long count = menuRepository.countChildMenus();
        String nextCode = "C" + String.format("%04d", count + 1);
        menu.setCode(nextCode);
        menuRepository.save(menu);
        log.info("Sub Menu saved: {}", menu.getCode());
        return true;
    }
    //Autocomplete : Parent Menu
    public List<Menu> searchAutocompleteParentMenus(String q) {
        log.info("Getting  Menus ");
        //List<Menu> menus =   menuRepository.findByNameTHContainingIgnoreCaseOrNameENContainingIgnoreCaseOrCodeContainingIgnoreCase(q, q ,q);
        if (q == null || q.trim().isEmpty()) {
            return List.of();
        }
        List<Menu> menus = menuRepository.searchAutocompleteParentMenus(
                q.trim(),
                PageRequest.of(0, 10) // limit 10 items
        );
        log.info("Total Menu: {}", menus.size());

        return menus;
    }
    //Datatable : Sub Menu
    public List<Menu> getDatableSubMenusByParentCode(String code) {
        log.info("Getting Sub Menus ");
        List<Menu> menus =  menuRepository.getDatableSubMenusByParentCode(code);
        log.info("Total Sub Menu : {}", menus.size());
        return menus;
    }





}
