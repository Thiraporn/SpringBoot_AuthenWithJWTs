package com.jwt.authentication.payload.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
@Builder
public class JwtResponse {

    private String accessToken;

    @Builder.Default
    private String type = "Bearer";

    private String username;
    private String refreshToken;
    private List<String> roles;

}