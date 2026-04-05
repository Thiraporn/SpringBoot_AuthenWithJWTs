package com.jwt.authentication.payload.request;
import jakarta.validation.constraints.*;
import lombok.*;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignupRequest {

    @NotBlank
    @Size(max = 50)
    private String user;

    @NotBlank
    @Size(min = 8, max = 40)
    private String pwd;
}