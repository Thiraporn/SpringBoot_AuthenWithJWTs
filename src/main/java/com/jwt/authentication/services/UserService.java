package com.jwt.authentication.services;
import com.ana.common.security.libs.advices.ApiException;
import com.jwt.authentication.models.ERole;
import com.jwt.authentication.models.Menu;
import com.jwt.authentication.models.Role;
import com.jwt.authentication.models.User;
import com.jwt.authentication.repository.RoleRepository;
import com.jwt.authentication.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@Service
public class UserService {
    @Autowired
    private  UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private  PasswordEncoder encoder;
    public List<User> getAllUsers() {
        log.info("Getting all users from fact_orders");
        List<User> users =  userRepository.findAll();
        log.info("Total users: {}", users.size());
        return users;
    }
    public boolean doSaveUser(User user) {

        if (userRepository.existsByUsername(user.getUsername())) {
            throw new ApiException(  HttpStatus.BAD_REQUEST,  "SAVE_USER_IS_FAIL", "Error: Username is already taken!" );
        }

        // ดึง role master จาก DB
        Map<ERole, String> roleMap =
                roleRepository.findAll()
                        .stream()
                        .collect(Collectors.toMap(
                                Role::getName,
                                Role::getCode
                        ));


        // role จาก frontend
        //List<ERole> inputRoles = user.getRoles().keySet().stream().toList();
        //กัน null + แปลงข้อมูล roles ให้ปลอดภัยก่อนใช้งาน
        List<ERole> inputRoles = user.getRoles() == null  ? List.of()   : new ArrayList<>(user.getRoles().keySet());

        Map<ERole, String> userRoles = new HashMap<>();

        if (inputRoles.isEmpty()) {
            //verified role USER is existing
            Role defaultRole = roleRepository.findByName(ERole.USER) .orElseThrow(() -> new ApiException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "ROLE_NOT_FOUND",
                    "Default role not found"
            ));
            userRoles.put(defaultRole.getName(), defaultRole.getCode());
        } else {
            for (ERole role : inputRoles) {
                String code = roleMap.get(role);
                if (code == null) {
                    throw new ApiException(  HttpStatus.BAD_REQUEST,  "INVALID_ROLE",   "Role not found: " + role );
                }
                userRoles.put(role, code);

            }
        }
        //Role
        user.setRoles(userRoles);
        //encrypt the password
        user.setPassword(encoder.encode(user.getPassword()));

        userRepository.save(user);

        log.info("User saved: {}", user.getUsername());
        return true;
    }
    public boolean updateUser(User userObj) {
        //find user
        User user = userRepository.findByUsername(userObj.getUsername())
                .orElseThrow(() -> new ApiException(
                        HttpStatus.NOT_FOUND,
                        "USER_NOT_FOUND",
                        "User not found"
                ));

        // 1. update basic info
        if (userObj.getNameTH() != null) {
            user.setNameTH(userObj.getNameTH());
        }

        // 2. update password (optional) ห้าม update ในนี้ ---> future feature : change password
        /*if (userObj.getPassword() != null && !userObj.getPassword().isBlank()) {
            user.setPassword(encoder.encode(userObj.getPassword()));
        }*/

        // 3. handle roles (multi-role)
        Map<ERole, String> roleMap =
                roleRepository.findAll()
                        .stream()
                        .collect(Collectors.toMap(Role::getName, Role::getCode));

        //กัน null + แปลงข้อมูล roles ให้ปลอดภัยก่อนใช้งาน
        Map<ERole, String> inputRoles = Optional.ofNullable(userObj.getRoles()).orElse(Collections.emptyMap());
        Map<ERole, String> newRoles = new HashMap<>();

        if (inputRoles.isEmpty()) {
            Role defaultRole = roleRepository.findByName(ERole.USER) .orElseThrow(() -> new ApiException(
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "ROLE_NOT_FOUND",
                            "Default role not found"
                    ));
            newRoles.put(defaultRole.getName(), defaultRole.getCode());
        } else {
            for (Map.Entry<ERole, String> entry : inputRoles.entrySet()) {
                ERole role = entry.getKey();
                String code = entry.getValue();
                if (code == null) {
                    throw new ApiException( HttpStatus.BAD_REQUEST, "INVALID_ROLE", "Invalid role: " + role );
                }
                newRoles.put(role, code);
            }
        }

        // overwrite roles
        user.setRoles(newRoles);
        user.setInfo(userObj.getInfo());

        userRepository.save(user);

        return true;
    }
    //Autocomplete : Users
    public List<User> searchAutocompleteUsers(String q) {
        log.info("Getting  Users ");
        if (q == null || q.trim().isEmpty()) {
            return List.of();
        }
        String keyword = q.toLowerCase().trim();
        //Query MongoDB
        //List<User> users = userRepository.searchAutocompleteUsers(keyword);

        //Query Java
        List<User> users = userRepository.findAll().stream()
                .filter(user ->
                        (user.getUsername() != null &&
                                user.getUsername().toLowerCase().contains(keyword))
                                ||
                                (user.getNameTH() != null &&
                                        user.getNameTH().toLowerCase().contains(keyword))
                )
                .limit(10) // autocomplete ต้อง limit
                .toList();;

        log.info("Total Users: {}", users.size());

        return  users;
    }




}
