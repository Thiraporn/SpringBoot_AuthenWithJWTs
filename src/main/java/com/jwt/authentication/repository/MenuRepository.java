package com.jwt.authentication.repository;

import com.jwt.authentication.models.Menu;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface MenuRepository extends MongoRepository<Menu, String> {
}