package com.jwt.authentication.repository;

import com.jwt.authentication.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends MongoRepository<User,String> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Optional<User> findByRefreshTokensContaining(String refreshToken);
    boolean existsByRefreshTokensContaining(String refreshToken);
    //MongoDB
    @Query("{ $or: [ " +
            "{ username: { $regex: ?0, $options: 'i' } }, " +
            "{ nameTH: { $regex: ?0, $options: 'i' } } " +
            "] }")
    List<User> searchAutocompleteUsers(String q);

//    //JPA
//    @Query("""
//        SELECT u FROM User u
//        WHERE LOWER(u.username) LIKE LOWER(CONCAT('%', :q, '%'))
//           OR LOWER(u.nameTH) LIKE LOWER(CONCAT('%', :q, '%'))
//        """)
//    List<User> search(@Param("q") String q);

}
