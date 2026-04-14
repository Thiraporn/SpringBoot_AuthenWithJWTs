package com.jwt.authentication.models;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "users")
public class User {

    @Id
    private String id;

    @NotBlank
    @Size(max = 20)
    private String username;

    @NotBlank
    @Size(max = 120)
    private String password;

    private String refreshToken;
    private Long refreshTokenExpiry;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    //@DBRef
    //@Builder.Default
    //private Set<Role> roles = new HashSet<>();
    private Map<ERole, String>  roles;


}
