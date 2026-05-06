package com.jwt.authentication.repository;

import com.jwt.authentication.models.Menu;
import com.jwt.authentication.models.Permission;
import org.springframework.data.mongodb.repository.Aggregation;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

public interface PermissionRepository extends MongoRepository<Permission, String> {
    @Query("{ 'roleCode': { $in: ?0 }, 'enabled': true }")
    List<Permission> findActivePermissionsByRoles(List<String> roles);
    List<Permission> findByRoleCodeInAndEnabledTrue(List<String> roleCodes);




}