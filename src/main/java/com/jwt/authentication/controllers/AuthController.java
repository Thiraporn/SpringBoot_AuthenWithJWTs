package com.jwt.authentication.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.jwt.authentication.models.User;
import com.jwt.authentication.payload.request.LoginRequest;
import com.jwt.authentication.payload.response.JwtResponse;
import com.jwt.authentication.payload.response.MessageResponse;
import com.jwt.authentication.repository.RoleRepository;
import com.jwt.authentication.repository.UserRepository;
import com.jwt.authentication.security.jwt.JwtUtils;
import com.jwt.authentication.security.services.UserDetailsImpl;
import com.jwt.authentication.security.services.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
//@RequestMapping("")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final UserDetailsServiceImpl userDetailsService;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/authen")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUser(), loginRequest.getPwd()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        //  1.Access Token
        String accessToken = jwtUtils.generateAccessToken(userDetails);
        // 2.Access Refresh Token from update Refresh Token (save DB)
        User updatedUser = userDetailsService.createOrUpdateRefreshToken(jwtUtils.generateRefreshToken(userDetails));
        // 3. สร้าง cookie refreshToken
        String refreshToken = updatedUser.getRefreshToken();

        // 4.set cookie
        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(accessToken);
        ResponseCookie refreshCookie = jwtUtils.generateRefreshJwtCookie(refreshToken);
        //5.roles
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        /*List<String> roles = getRolesFromJwt(token);

        List<GrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());*/

        // ส่งกลับ
        return ResponseEntity.ok()
                .headers(headers -> {
                    headers.add(HttpHeaders.SET_COOKIE, jwtCookie.toString());//ใส่ cookie
                    headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());//ใส่ cookie
                })
                .body(JwtResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .username(userDetails.getUsername())
                        .roles(roles)
                        .build()
                );
    }
    @RequestMapping(value = "/refreshtoken", method = RequestMethod.GET)
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
        String refreshToken = jwtUtils.getJwtRefreshFromCookies(request);
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Refresh Token is empty!"));
        }

        try {
            // 1. verify token เก่า   ตรวจ + ได้ UserDetails กลับมา
            User user = userDetailsService.verifyExpiration(refreshToken);


            UserDetailsImpl userDetails = UserDetailsImpl.build(user);// สร้าง UserDetails

            // 2. สร้าง access token ใหม่
            String newAccessToken = jwtUtils.generateAccessToken(userDetails);

            //3. rotate refresh token
            User updatedUser = userDetailsService.createOrUpdateRefreshToken(jwtUtils.generateRefreshToken(userDetails));
            String newRefreshToken = updatedUser.getRefreshToken();

            // 4. set cookie
            ResponseCookie accessCookie = jwtUtils.generateJwtCookie(newAccessToken);
            ResponseCookie refreshCookie = jwtUtils.generateRefreshJwtCookie(newRefreshToken);

            //5.roles
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            return ResponseEntity.ok()
                    .headers(headers -> {
                        headers.add(HttpHeaders.SET_COOKIE, accessCookie.toString());
                        headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
                    })
                    .body( JwtResponse.builder()
                            .accessToken(newAccessToken)
                            .refreshToken(newRefreshToken)
                            .username(userDetails.getUsername())
                            .roles(roles)
                            .build()
                    );

        } catch (RuntimeException e) {
            // token invalid → clear cookie
            ResponseCookie clearAccess = jwtUtils.getCleanJwtCookie();
            ResponseCookie clearRefresh = jwtUtils.getCleanJwtRefreshCookie();

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .headers(headers -> {
                        headers.add(HttpHeaders.SET_COOKIE, clearAccess.toString());
                        headers.add(HttpHeaders.SET_COOKIE, clearRefresh.toString());
                    })
                    .body(new MessageResponse("Refresh token invalid"));
        }

    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {

        String refreshToken = jwtUtils.getJwtRefreshFromCookies(request);
        User user = userRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Token not found"));

        // ลบ token
        user.setRefreshToken(null);
        user.setRefreshTokenExpiry(null);

        userRepository.save(user);

        ResponseCookie clearRefresh = jwtUtils.getCleanJwtCookie();
        ResponseCookie clearAccess = jwtUtils.getCleanJwtRefreshCookie();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, clearRefresh.toString())
                .header(HttpHeaders.SET_COOKIE, clearAccess.toString())
                .body(new MessageResponse("Logged out"));

    }


}
