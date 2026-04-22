package com.jwt.authentication.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private List<String> roles;
    private String message;

}
