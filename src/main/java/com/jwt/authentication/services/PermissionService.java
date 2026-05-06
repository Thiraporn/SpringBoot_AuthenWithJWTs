package com.jwt.authentication.services;
import com.jwt.authentication.models.Menu;
import com.jwt.authentication.models.Permission;
import com.jwt.authentication.models.Role;
import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.response.MenuResponse;
import com.jwt.authentication.repository.PermissionRepository;
import com.jwt.authentication.repository.RoleRepository;
import com.jwt.authentication.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@Service
public class PermissionService {
    @Autowired
    private PermissionRepository permissionRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    private final MongoTemplate mongoTemplate;

    public PermissionService(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }
    public List<Permission> getAllPermissions() {
        log.info("Getting all permissions ");
        List<Permission> permissions =  permissionRepository.findAll();
        log.info("Total permissions: {}", permissions.size());
        return permissions;
    }

    public boolean doPermissions(List<Permission> permissions) {
        for (Permission p : permissions) {
            Query query = new Query(
                    Criteria.where("roleCode").is(p.getRoleCode())
                            .and("menuCode").is(p.getMenuCode())
            );
            Update update = new Update()
                    .set("enabled", p.isEnabled());

            mongoTemplate.upsert(query, update, Permission.class);
            log.info("Permission saved: {}", p.toString());
        }


        return true;
    }

    public List<Permission> getAuthorizedPermission(Authentication auth) {
        log.info("Getting Permission By Current Authorized ");

        User user = userRepository.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));


        List<String> roles = user.getRoles()
                .keySet()
                .stream()
                .map(Enum::name)
                .toList();

        List<Permission> permissions = permissionRepository.findActivePermissionsByRoles(roles);
        log.info("Total Permission By  Current Authorized: {}", permissions.size());
        return permissions;
    }
//    public List<Menu> getMenusAuthorized(Authentication auth) {
//
//        User user = userRepository.findByUsername(auth.getName())
//                .orElseThrow(() -> new RuntimeException("User not found"));
//
//        List<String> roleCodes = user.getRoles()
//                .keySet()
//                .stream()
//                .map(Enum::name)
//                .toList();
//
//        return permissionRepository.findMenusByRoles(roleCodes);
//    }
    public List<MenuResponse> getMenusByUserAuthorized(Authentication auth) {

        // 1. get user
        User user = userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 2. extract roles
        List<String> roleCodes = new ArrayList<>(user.getRoles().values());

        // 3. validate roles exist in DB
        List<String> validRoles = roleRepository.findAllByCodeIn(roleCodes)
                .stream()
                .map(Role::getCode)
                .toList();

        if (validRoles.isEmpty()) {
            return Collections.emptyList();
        }
        System.out.println("roleCodes>>> {} "+roleCodes.toString());
        System.out.println("validRoles>>> {} "+validRoles.toString());

        // 4. get menus from permission aggregation
        List<Menu> menus = roleRepository.findMenusByRoles(validRoles);

        // 5. build tree (optional but recommended)
        return buildMenuTree(menus);
    }

    private List<MenuResponse> buildMenuTree(List<Menu> menus) {

        Map<String, MenuResponse> map = menus.stream()
                .collect(Collectors.toMap(
                        Menu::getCode,
                        this::toResponse
                ));

        List<MenuResponse> roots = new ArrayList<>();

        for (Menu menu : menus) {

            MenuResponse node = map.get(menu.getCode());

            if (menu.getMenuParent() == null || menu.getMenuParent().equals("00")) {
                roots.add(node);
            } else {
                MenuResponse parent = map.get(menu.getMenuParent());

                if (parent != null) {
                    parent.getChildren().add(node);
                }
            }
        }

        return roots;
    }
    private MenuResponse toResponse(Menu menu) {
        MenuResponse res = new MenuResponse();
        res.setCode(menu.getCode());
        res.setNameEN(menu.getNameEN());
        res.setUrl(menu.getUrl());
        res.setIcon(menu.getIcon());
        res.setColor(menu.getColor());
        return res;
    }



}
