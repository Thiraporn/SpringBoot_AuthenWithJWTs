package com.jwt.authentication.services;
import com.jwt.authentication.models.Permission;
import com.jwt.authentication.repository.PermissionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Service;

import java.util.List;


@Slf4j
@Service
public class PermissionService {
    @Autowired
    private PermissionRepository permissionRepository;

    private final MongoTemplate mongoTemplate;

    public PermissionService(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }
    public List<Permission> getAllPermissions() {
        log.info("Getting all permissions ");
        List<Permission> permissions =  permissionRepository.findAll();
        log.info("Total permissions: {}", permissions.size());
        return permissions;
    }

    public boolean doPermissions(List<Permission> permissions) {
        for (Permission p : permissions) {
            Query query = new Query(
                    Criteria.where("roleCode").is(p.getRoleCode())
                            .and("menuCode").is(p.getMenuCode())
            );
            Update update = new Update()
                    .set("enabled", p.isEnabled());

            mongoTemplate.upsert(query, update, Permission.class);
            log.info("Permission saved: {}", p.toString());
        }


        return true;
    }





}
