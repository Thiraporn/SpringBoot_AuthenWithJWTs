package com.jwt.authentication.services;

import com.ana.common.security.libs.advices.ApiException;
import com.jwt.authentication.models.Menu;
import com.jwt.authentication.payload.response.MenuResponse;
import com.jwt.authentication.repository.MenuRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Slf4j
@Service
public class MenuService {
    @Autowired
    private MenuRepository menuRepository;

    @Autowired
    private PermissionService permissionService;

    public List<Menu> getAllMenus() {
        log.info("Getting all Menus  ");
        List<Menu> menus =  menuRepository.findAll();
        log.info("Total Menu: {}", menus.size());
        return menus;
    }
    public List<MenuResponse> getAllMenusTree() {
        log.info("Getting all Menus  Tree");
        List<Menu> menus =  menuRepository.findAll();
        log.info("Total Menu Tree: {}", menus.size());
        // build tree (optional with no permissions)
        return permissionService.buildMenuTree(menus,null);
    }
    // generate new parent menu code
    public Menu doSaveMenu(Menu menu) {
        //long count = menuRepository.countByMenuParent("00");
        long count = menuRepository.countParentMenus();
        String nextCode = "P" + String.format("%04d", count + 1);
        menu.setCode(nextCode);
        Menu saveMenu = menuRepository.save(menu);
        log.info("Parent Menu saved: {}", menu.getCode());

        return saveMenu;
    }
    //  edit parent/child menu id
    public Menu doEditMenu(Menu menu) {
         Menu  retrieveMenu = menuRepository.findById(menu.getId()).orElseThrow(() ->
                 new ApiException(HttpStatus.INTERNAL_SERVER_ERROR,  "NOT_FOUND_DATA", "Error:  Menu is not found" ));

        log.info("Retrieve  Menu  : {}", retrieveMenu );
        retrieveMenu.setNameEN(menu.getNameEN());
        retrieveMenu.setNameTH(menu.getNameTH());
        retrieveMenu.setNameJP(menu.getNameJP());
        retrieveMenu.setUrl(menu.getUrl());
        retrieveMenu.setInfo(menu.getInfo());
        retrieveMenu.setStatus(menu.getStatus());
        retrieveMenu.setIcon(menu.getIcon());

        return menuRepository.save(retrieveMenu);
    }
    // generate new sub menu code
    public Menu doSaveSubMenu(Menu menu) {
        //long count = menuRepository.countByMenuParentNot("00");
        long count = menuRepository.countChildMenus();
        String nextCode = "C" + String.format("%04d", count + 1);
        menu.setCode(nextCode);
        Menu saveMenu = menuRepository.save(menu);
        log.info("Sub Menu saved: {}", menu.getCode());
        return saveMenu;
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
