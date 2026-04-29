package com.jwt.authentication.services;
import com.jwt.authentication.models.ERole;
import com.jwt.authentication.models.Role;
import com.jwt.authentication.models.User;
import com.jwt.authentication.repository.RoleRepository;
import com.jwt.authentication.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
@Service
public class UserService {
    @Autowired
    private  UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    public List<User> getAllUsers() {
        log.info("Getting all users from fact_orders");
        List<User> users =  userRepository.findAll();
        log.info("Total users: {}", users.size());
        return users;
    }
    public boolean doSaveUser(User user) {

        // ดึง role master จาก DB
        Map<ERole, String> roleMap =
                roleRepository.findAll()
                        .stream()
                        .collect(Collectors.toMap(
                                Role::getName,
                                Role::getCode
                        ));

        // role จาก frontend
        List<ERole> inputRoles = user.getRoles().keySet().stream().toList();

        Map<ERole, String> userRoles = new HashMap<>();

        for (ERole role : inputRoles) {
            userRoles.put(role, roleMap.get(role));
        }

        user.setRoles(userRoles);

        userRepository.save(user);

        log.info("User saved: {}", user.getUsername());
        return true;
    }




}
