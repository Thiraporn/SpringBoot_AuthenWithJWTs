package com.jwt.authentication.repository;

import com.jwt.authentication.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User,String> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Optional<User> findByRefreshTokensContaining(String refreshToken);
    boolean existsByRefreshTokensContaining(String refreshToken);

}
