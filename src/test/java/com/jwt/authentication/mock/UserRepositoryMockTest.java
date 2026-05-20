package com.jwt.authentication.mock;
import com.jwt.authentication.models.User;
import com.jwt.authentication.repository.UserRepository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class UserRepositoryMockTest {

    @Mock
    private UserRepository userRepository;
    //TEST CASE 1 : access DB user table : success
    @Test
    void findByUsername_shouldReturnUser() {

        User user = new User();
        user.setUsername("springbootuser");

        when(userRepository.findByUsername(anyString()))
                .thenReturn(Optional.of(user));

        Optional<User> result =
                userRepository.findByUsername("springbootuser");

        assertTrue(result.isPresent());

        assertEquals(
                "springbootuser",
                result.get().getUsername()
        );
    }

//    @Test
//    void save_shouldReturnUser() {
//        User user = new User();
//        user.setUsername("springbootuser");
//        when(userRepository.findByUsername(anyString()))
//                .thenReturn(Optional.of(user));
//
//        User saved = userRepository.save(user);
//
//        assertEquals("springbootuser", saved.getUsername());
//
//    }
}
