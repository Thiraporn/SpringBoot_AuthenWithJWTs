package com.jwt.authentication.models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "menus")
@Data
public class Menu {

    @Id
    private String id;

    private String code;
    private String nameTH;
    private String nameJP;
    private String nameEN;
    private String menuParent;
    private String info;
    private String url;
    private EStatus status = EStatus.UNDEFINED;
}
