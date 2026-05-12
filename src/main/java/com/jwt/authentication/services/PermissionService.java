package com.jwt.authentication.services;
import com.jwt.authentication.models.*;
import com.jwt.authentication.payload.response.MenuResponse;
import com.jwt.authentication.repository.MenuRepository;
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
    @Autowired
    private MenuRepository menuRepository;

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
    //Menu Group MANAGEMENT
    public List<MenuResponse> getManagementMenusByUserAuthorized(Authentication auth) {

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
        return buildMenuTree(menus,null);
    }
    private List<MenuResponse> buildMenuTree( List<Menu> menus,   Map<String, List<String>> permissionMap) {
        Map<String, List<String>> safePermissionMap =  permissionMap != null ? permissionMap : Collections.emptyMap();
        Map<String, MenuResponse> map =  menus.stream() .collect(Collectors.toMap(
                                Menu::getCode,
                                m -> toResponse(m, safePermissionMap)
                        ));

        List<MenuResponse> roots = new ArrayList<>();
        for (Menu menu : menus) {
            MenuResponse node = map.get(menu.getCode());
            if (menu.getMenuParent() == null || "00".equals(menu.getMenuParent())) {
                roots.add(node);
            } else {
                MenuResponse parent =  map.get(menu.getMenuParent());
                if (parent != null) {
                    parent.getChildren().add(node);
                } else {
                    roots.add(node);
                }
            }
        }

        return roots;
    }

    private MenuResponse toResponse(Menu menu,   Map<String, List<String>> permissionMap) {
        MenuResponse res = new MenuResponse();
        res.setCode(menu.getCode());
        res.setNameEN(menu.getNameEN());
        res.setUrl(menu.getUrl());
        res.setIcon(menu.getIcon());
        res.setColor(menu.getColor());
        res.setGroupCode(menu.getGroupCode());
        res.setDescription(menu.getNameEN());
        res.setRequiredPermissions(  permissionMap.getOrDefault(  menu.getCode(),  new ArrayList<>()  ) );
        return res;
    }
    //Menu ALL Group
    public List<MenuResponse> getAllMenusByUserAuthorized(Authentication auth) {
         // 1. get user
        User user = userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        // 2. extract roles
        List<String> roleCodes = new ArrayList<>(user.getRoles().values());
        // 3. validate roles exist in DB
        // 3. get roles as map (replace validRoles)
        Map<String, ERole> roleMap =
                roleRepository.findAllByCodeIn(roleCodes)
                        .stream()
                        .collect(Collectors.toMap(
                                Role::getCode,
                                Role::getName
                        ));

        // 4. empty check (replace validRoles.isEmpty())
        if (roleMap.isEmpty()) {
            return Collections.emptyList();
        }

        Set<String> validRoleCodes = roleMap.keySet();

        // 5. get permissions (แทน $lookup)
        List<Permission> permissions =
                permissionRepository.findByRoleCodeInAndEnabledTrue(validRoleCodes);

        // 6. group permission by menuCode  map (menuCode → roles)
        Map<String, List<String>> permissionMap =
                permissions.stream()
                        .collect(Collectors.groupingBy(
                                Permission::getMenuCode,
                                Collectors.mapping(
                                        p -> {
                                            ERole role = roleMap.get(p.getRoleCode());
                                            return role != null ? role.name() : null;
                                        },
                                        Collectors.toList()
                                )
                        ));

        // 7. extract menu codes
        List<String> menuCodes = permissions.stream()
                .map(Permission::getMenuCode)
                .distinct()
                .toList();

        // 8. fetch menus (แทน join menus) and sort menus
        List<Menu> menus = menuRepository.findAllByCodeIn(menuCodes);

        // 9. filter business rules : get menus from permission filter business rules (แทน $match)
        List<Menu> filtered = menus.stream()
                .filter(m ->  EStatus.ACTIVE.equals(m.getStatus()))
                .filter(m -> !Objects.equals(m.getGroupCode(), "HOME"))
                .sorted( Comparator.comparing( Menu::getCode ) )
                .toList();
        // 10.Empty
        if (filtered.isEmpty()) {
           return Collections.emptyList();
        }



        // 11.  build tree (with permission)
         return buildMenuTree(filtered, permissionMap);

    }




}
//// 4. find permissions
//List<Permission> permissions = permissionRepository.findByRoleCodeInAndEnabledTrue(validRoles);
//        if (permissions.isEmpty()) {
//        return Collections.emptyList();
//        }
//// 5. extract menu codes
//List<String> menuCodes =
//        permissions.stream()
//                .map(Permission::getMenuCode)
//                .distinct()
//                .toList();
//        System.out.println( "menuCodes >>> " + menuCodes );
//
//// 6. find menus
//List<Menu> menus = menuRepository.findByCodeInAndStatus(  menuCodes, "ACTIVE"  );
//
//        if (menus.isEmpty()) {
//        return Collections.emptyList();
//        }
//                // 7. sort menus
//                menus.sort(
//        Comparator.comparing(Menu::getCode)
//        );
//
//                // 8. build tree (optional but recommended)
//                return buildMenuTree(menus);