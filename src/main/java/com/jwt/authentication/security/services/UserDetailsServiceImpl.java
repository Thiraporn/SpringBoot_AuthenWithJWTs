package com.jwt.authentication.security.services;

import com.jwt.authentication.models.User;
import com.jwt.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDetailsImpl.build(user);
    }
    public User createOrUpdateRefreshToken(User userObj) {
        User user = userRepository.findByUsername(userObj.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        //String newToken = UUID.randomUUID().toString();
        //long expiry = System.currentTimeMillis() + userObj.getRefreshTokenExpiry();
        user.setRefreshToken(userObj.getRefreshToken());
        user.setRefreshTokenExpiry(userObj.getRefreshTokenExpiry());

        return userRepository.save(user); // update user
    }

    public User verifyExpiration(String token) {
        User user = userRepository.findByRefreshToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (user.getRefreshTokenExpiry() < System.currentTimeMillis()) {
            throw new RuntimeException("Refresh token expired");
        }

        return user;
    }

}
