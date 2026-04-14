package com.jwt.authentication.security.services;

import com.jwt.authentication.advices.ApiException;
import com.jwt.authentication.models.User;
import com.jwt.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //valid user
        User user = userRepository.findByUsername(username).orElseThrow(() -> new ApiException(  HttpStatus.INTERNAL_SERVER_ERROR,  "USER_NOT_FOUND", "User Not Found with username: " + username ));

        return UserDetailsImpl.build(user);
    }
    public User createOrUpdateRefreshToken(User userObj) {
        //valid user
        User user = userRepository.findByUsername(userObj.getUsername()).orElseThrow(() -> new ApiException(  HttpStatus.INTERNAL_SERVER_ERROR,  "USER_NOT_FOUND", "User Not Found with username: " + userObj.getUsername()));

        //set new token
        user.setRefreshToken(userObj.getRefreshToken());
        user.setRefreshTokenExpiry(userObj.getRefreshTokenExpiry());

        return userRepository.save(user); // update user
    }

    public User verifyExpiration(String token) {
        //valid user
        User user = userRepository.findByRefreshToken(token).orElseThrow(() -> new ApiException(  HttpStatus.INTERNAL_SERVER_ERROR,  "TOKEN_NOT_FOUND", "Invalid refresh token" ));

        if (user.getRefreshTokenExpiry() < System.currentTimeMillis()) {
            throw new ApiException(  HttpStatus.INTERNAL_SERVER_ERROR,  "TOKEN_EXPIRED", "Refresh token expired" );
        }

        return user;
    }

}
