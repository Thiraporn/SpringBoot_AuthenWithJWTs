package com.jwt.authentication.repository;

import com.jwt.authentication.models.ERole;
import com.jwt.authentication.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface  RoleRepository extends  MongoRepository<Role,String> {
    Optional<Role> findByName(ERole eRole);
}
