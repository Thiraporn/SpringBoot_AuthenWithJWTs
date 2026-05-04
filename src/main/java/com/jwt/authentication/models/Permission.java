package com.jwt.authentication.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

//MongoDB data format JSON
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "permissions")
public class Permission {
    @Id
    private String id;
    private String roleCode;
    private String menuCode;

    private boolean enabled;
}
