package com.jwt.authentication.payload.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MenuResponse {
    private String code;
    private String nameEN;
    private String url;
    private String icon;
    private String color;
    @Builder.Default
    private List<MenuResponse> children = new ArrayList<>();
}