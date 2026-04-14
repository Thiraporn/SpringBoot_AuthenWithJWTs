package com.jwt.authentication.controllers;

import com.jwt.authentication.payload.request.LoginRequest;
import com.jwt.authentication.payload.response.JwtResponse;
import com.jwt.authentication.payload.response.MessageResponse;
import com.jwt.authentication.services.JwtTokenService;
import com.jwt.authentication.services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
public class AuthController {
    private final JwtTokenService jwtTokenService;
    private final AuthService authService;

    @PostMapping("/authen")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        //log in
        JwtResponse jwtResponse = authService.login(loginRequest);

        // set cookie
        ResponseCookie jwtCookie = jwtTokenService.generateJwtCookie(jwtResponse.getAccessToken());
        ResponseCookie refreshCookie = jwtTokenService.generateRefreshJwtCookie(jwtResponse.getRefreshToken());


        // response
        return ResponseEntity.ok()
                .headers(headers -> {
                    headers.add(HttpHeaders.SET_COOKIE, jwtCookie.toString());//ใส่ cookie
                    headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());//ใส่ cookie
                })
                .body(new MessageResponse("Authentication Success"));
                 //.body(jwtResponse);
    }

    @GetMapping( "/refreshtoken")
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
            //refresh
            JwtResponse jwtResponse = authService.refreshToken(request);

            // set cookie
            ResponseCookie jwtCookie = jwtTokenService.generateJwtCookie(jwtResponse.getAccessToken());
            ResponseCookie refreshCookie = jwtTokenService.generateRefreshJwtCookie(jwtResponse.getRefreshToken());

            // response
            return ResponseEntity.ok()
                    .headers(headers -> {
                        headers.add(HttpHeaders.SET_COOKIE, jwtCookie.toString());//ใส่ cookie
                        headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());//ใส่ cookie
                    }).body(new MessageResponse("Refresh token Success"));
                    //.body(jwtResponse);

    }
    @RequestMapping(value = "/sign-out", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<?> logout(HttpServletRequest request) {
        //logout
        authService.logout(request);
        // remove cookie
        ResponseCookie clearRefresh = jwtTokenService.getCleanJwtCookie();
        ResponseCookie clearAccess = jwtTokenService.getCleanJwtRefreshCookie();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, clearRefresh.toString())
                .header(HttpHeaders.SET_COOKIE, clearAccess.toString())
                .body(new MessageResponse("Logged out"));

    }


}
