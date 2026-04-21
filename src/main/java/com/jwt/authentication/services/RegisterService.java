package com.jwt.authentication.services;

import com.ana.common.security.libs.advices.ApiException;
import com.jwt.authentication.models.ERole;
import com.jwt.authentication.models.Role;
import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.request.SignupRequest;
import com.jwt.authentication.payload.response.MessageResponse;
import com.jwt.authentication.repository.RoleRepository;
import com.jwt.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class RegisterService {
    private final UserRepository userRepository;
    private  final RoleRepository roleRepository;
    private  final PasswordEncoder encoder;

    public MessageResponse register(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUser())) {
            throw new ApiException(  HttpStatus.BAD_REQUEST,  "REGISTER_IS_FAIL", "Error: Username is already taken!" );
        }

        if (userRepository.existsByUsername(signUpRequest.getUser())) {
            throw new ApiException(  HttpStatus.BAD_REQUEST,  "REGISTER_IS_FAIL", "Error: Email is already in use!" );
        }

        // Create new user's account
        User user = new User(signUpRequest.getUser(),encoder.encode(signUpRequest.getPwd()));

       // Create default role for new user's account
        Map<ERole, String> roles = new HashMap<>();
        Role userRole = roleRepository.findByName(ERole.USER).orElseThrow(() ->  new ApiException(HttpStatus.INTERNAL_SERVER_ERROR,  "REGISTER_IS_FAIL", "Error: Role not found" ));
        roles.put(userRole.getName(), userRole.getCode());

        //save user
        user.setRoles(roles);
        userRepository.save(user);

        return MessageResponse.builder()
                .message("User registered successfully!")
                .build();

    }
}
