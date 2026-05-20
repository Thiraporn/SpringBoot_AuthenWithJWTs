package com.jwt.authentication.unit;


import com.ana.common.security.libs.payload.MessageResponse;
import com.jwt.authentication.models.ERole;
import com.jwt.authentication.models.Role;
import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.request.SignupRequest;
import com.jwt.authentication.repository.RoleRepository;
import com.jwt.authentication.repository.UserRepository;
import com.jwt.authentication.services.RegisterService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
//เป้าหมาย: test token generation / validation
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;//คือ fake repository Mockito test Mockito test รับ call ไว้เฉย ๆ

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private RegisterService registerService;

    @Mock
    private RoleRepository roleRepository;//คือ fake repository Mockito test Mockito test รับ call ไว้เฉย ๆ

    //TEST CASE 1 : encodePassword :success
    @Test
    void encodePassword_shouldWork() {

        when(passwordEncoder.encode("1234"))
                .thenReturn("hashedPassword");

        String result =
                passwordEncoder.encode("1234");

        assertEquals("hashedPassword", result);
    }

    //TEST CASE 2 : Register User :success
    @Test
    void register_shouldSuccess_whenUsernameNotExist() {

        SignupRequest user = new SignupRequest();
        user.setUser("TT4@gmail.com");
        user.setPwd("1234");

        Role role = new Role();
        role.setName(ERole.USER);

        when(userRepository.existsByUsername("TT4@gmail.com"))
                .thenReturn(false);

        when(passwordEncoder.encode("1234"))
                .thenReturn("hashedPassword");

        when(roleRepository.findByName(ERole.USER))
                .thenReturn(Optional.of(role));

        MessageResponse result =
                registerService.register(user);//คือ fake repository Mockito test Mockito test รับ call ไว้เฉย ๆ

        assertNotNull(result);

        assertEquals(
                "User registered successfully!",
                result.getMessage()
        );

        verify(userRepository)
                .save(any(User.class));//คือ fake repository Mockito test Mockito test รับ call ไว้เฉย ๆ
    }
    //TEST CASE 3 : Register User : fail
    @Test
    void register_shouldFail_whenUsernameAlreadyExist() {
        User existing = new User();
        existing.setUsername("TT2@gmail.com");

//        when(userRepository.findByUsername("TT2@gmail.com"))
//                .thenReturn(Optional.of(existing));
        when(userRepository.existsByUsername("TT2@gmail.com"))
                .thenReturn(false);

        assertThrows(RuntimeException.class, () -> {
            SignupRequest  user = new SignupRequest();
            user.setUser("TT2@gmail.com");
            user.setPwd("1234");
            registerService.register(user);
        });
    }
}