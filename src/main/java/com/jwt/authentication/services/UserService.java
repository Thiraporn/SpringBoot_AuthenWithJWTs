package com.jwt.authentication.services;

import com.jwt.authentication.models.User;
import com.jwt.authentication.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;


@Slf4j
@Service
public class UserService {
    @Autowired
    private  UserRepository userRepository;

    public List<User> getAllUsers() {
        log.info("Getting all users from fact_orders");
        List<User> users =  userRepository.findAll();
        log.info("Total users: {}", users.size());
        return users;
    }




}
