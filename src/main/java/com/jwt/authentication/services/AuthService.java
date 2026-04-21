package com.jwt.authentication.services;

import com.ana.common.security.libs.advices.ApiException;
import com.ana.common.security.libs.jsonwebtoken.CookieConfig;
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

import java.util.List;
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

    public JwtResponse login(LoginRequest loginRequest) {
//        try {
            //  1. authenticate
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUser(), loginRequest.getPwd()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            //  2.Access Token
            String accessToken = jwtTokenService.generateAccessToken(userDetails);
            // 3.Access Refresh Token from update Refresh Token (save DB)
            User updatedUser = userDetailsService.createOrUpdateRefreshToken(jwtTokenService.generateRefreshToken(userDetails));
            // 4. สร้าง cookie refreshToken
            String refreshToken = updatedUser.getRefreshToken();
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
//        } catch (RuntimeException e) {
//            throw new ApiException(  HttpStatus.UNAUTHORIZED,  "LOGIN_IS_FAIL", "Fail during Login..." );
//        }

    }

    public JwtResponse refreshToken(HttpServletRequest request) {
        try {
            String refreshToken = cookieConfig.getJwtRefreshFromCookies(request);
            if (refreshToken == null || refreshToken.isEmpty()) {
                //return ResponseEntity.badRequest().body(new MessageResponse("Refresh Token is empty!"));
                throw new ApiException(HttpStatus.UNAUTHORIZED, "REFRESH_TOKEN_EMPTY", "Refresh Token is empty!");
            }

            // 1. verify token เก่า   ตรวจ + ได้ UserDetails กลับมา
            User user = userDetailsService.verifyExpiration(refreshToken);


            UserDetailsImpl userDetails = UserDetailsImpl.build(user);// สร้าง UserDetails

            // 2. สร้าง access token ใหม่
            String newAccessToken = jwtTokenService.generateAccessToken(userDetails);

            //3. rotate refresh token
            User updatedUser = userDetailsService.createOrUpdateRefreshToken(jwtTokenService.generateRefreshToken(userDetails));
            String newRefreshToken = updatedUser.getRefreshToken();

            // 4. set cookie
            ResponseCookie accessCookie = cookieConfig.generateJwtCookie(newAccessToken);
            ResponseCookie refreshCookie = cookieConfig.generateRefreshJwtCookie(newRefreshToken);

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
        } catch (ApiException e) {
            throw e; // ส่งต่อของเดิม
        } catch (RuntimeException e) {
            throw new ApiException(  HttpStatus.UNAUTHORIZED,  "REFRESH_TOKEN_INVALID", "Refresh Token is empty!" );
        }
    }
    public boolean logout(HttpServletRequest request) {
        try {
            //valid user
            String refreshToken = cookieConfig.getJwtRefreshFromCookies(request);
            if (!StringUtils.hasText(refreshToken)) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "REFRESH_TOKEN_EMPTY", "Nerver sign-in ");
            }

            User user = userRepository.findByRefreshToken(refreshToken).orElseThrow(() -> new ApiException(  HttpStatus.BAD_REQUEST,  "TOKEN_NOT_FOUND", "Token not found" ));

            // remove token
            user.setRefreshToken(null);
            user.setRefreshTokenExpiry(null);

            userRepository.save(user);

        } catch (ApiException e) {
                throw e; // ส่งต่อของเดิม
        } catch (RuntimeException e) {
            throw new ApiException(  HttpStatus.UNAUTHORIZED,  "LOGOUT_IS_FAIL", "Fail during Logout..." );
        }

        return true;
    }

}
