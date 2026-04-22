package com.jwt.authentication.services;

import com.ana.common.security.libs.advices.ApiException;
import com.ana.common.security.libs.jsonwebtoken.CookieConfig;
import com.ana.common.security.libs.jsonwebtoken.JwtUtils;
import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.request.LoginRequest;
import com.jwt.authentication.payload.response.JwtResponse;
import com.jwt.authentication.repository.RoleRepository;
import com.jwt.authentication.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtTokenService jwtTokenService;
    private final CookieConfig cookieConfig;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtils jwtUtils;//tool ในการตรวจสอบว่า JWT ถูกต้องไหม
    public JwtResponse login(LoginRequest loginRequest) {
            //  1. authenticate
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUser(), loginRequest.getPwd()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            //  2.Access Token
            String accessToken = jwtTokenService.generateAccessToken(userDetails);
            // 3.Access Refresh Token from add Refresh Token (save DB)
            String refreshToken = jwtTokenService.generateRefreshToken(userDetails);
            User user = userRepository.findByUsername(userDetails.getUsername()).orElseThrow(() -> new ApiException(
                    HttpStatus.NOT_FOUND,
                    "USER_NOT_FOUND",
                    "User Not Found with username: " + loginRequest.getUser()
            ));
            user.getRefreshTokens().add(refreshToken);
            userRepository.save(user);


            //5.roles
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            return JwtResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .username(userDetails.getUsername())
                    .roles(roles)
                    .build();


    }

    public JwtResponse refreshToken(HttpServletRequest request) {
            String refreshToken = cookieConfig.getJwtRefreshFromCookies(request);
            if (refreshToken == null || refreshToken.isEmpty()) {
                //return ResponseEntity.badRequest().body(new MessageResponse("Refresh Token is empty!"));
                throw new ApiException(HttpStatus.UNAUTHORIZED, "REFRESH_TOKEN_EMPTY", "Refresh Token is empty!");
            }
            if (!jwtUtils.validateJwtToken(refreshToken)) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "Invalid refresh token");
            }
            // 1. verify token เก่า   ตรวจ + ได้ UserDetails กลับมา
            // REUSE DETECTION
            Optional<User> user = userRepository.findByRefreshTokensContaining(refreshToken);
            if (user.isEmpty()) {
                String username = jwtUtils.getUserNameFromJwtToken(refreshToken);
                User hackedUser = userRepository.findByUsername(username)
                        .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "USER_NOT_FOUND", "User not found"));

                hackedUser.setRefreshTokens(new ArrayList<>()); // kill ทุก session
                userRepository.save(hackedUser);
                throw new ApiException(HttpStatus.FORBIDDEN, "TOKEN_REUSE", "Refresh token reuse detected");
            }
            User saveUser = user.get();
            UserDetailsImpl userDetails = UserDetailsImpl.build(saveUser);// สร้าง UserDetails

            // 2. สร้าง access token ใหม่
            String newAccessToken = jwtTokenService.generateAccessToken(userDetails);

            //3. rotate refresh token
            String newRefreshToken = jwtTokenService.generateRefreshToken(userDetails);

            //4.rotation
            saveUser.getRefreshTokens().remove(refreshToken);   //  ลบตัวเก่า
            saveUser.getRefreshTokens().add(newRefreshToken);   //  ใส่ตัวใหม่
            userRepository.save(saveUser);


            //5.roles
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            return JwtResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .username(userDetails.getUsername())
                    .roles(roles)
                    .build();

    }
    public boolean logout(HttpServletRequest request) {
        //valid user
        String refreshToken = cookieConfig.getJwtRefreshFromCookies(request);
        if (!StringUtils.hasText(refreshToken)) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "REFRESH_TOKEN_EMPTY", "Nerver sign-in ");
        }
        User user = userRepository.findByRefreshTokensContaining(refreshToken)
                .orElseThrow(() -> new ApiException(
                        HttpStatus.BAD_REQUEST,
                        "TOKEN_NOT_FOUND",
                        "Token not found"
                ));

        // ลบ refresh token ออกจาก list
        user.setRefreshTokens(
                user.getRefreshTokens()
                        .stream()
                        .filter(t -> !t.equals(refreshToken))
                        .toList()
        );
        userRepository.save(user);

        return true;
    }


}
