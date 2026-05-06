package com.jwt.authentication.repository;

import com.jwt.authentication.models.Menu;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface MenuRepository extends MongoRepository<Menu, String> {
    long countByMenuParent(String menuParent);
    long countByMenuParentNot(String menuParent);


    @Query("{ $or: [ " +
            "{ nameTH: { $regex: ?0, $options: 'i' } }, " +
            "{ nameEN: { $regex: ?0, $options: 'i' } }, " +
            "{ code: { $regex: ?0, $options: 'i' } } ] }")
    List<Menu> searchAutocompleteParentMenus(String q, Pageable pageable);

    @Query("{ 'menuParent': { $nin: ['00', null] } }")
    long countChildMenus();

    @Query("{ 'menuParent': { $eq: '00' } }")//not null
    long countParentMenus();

    @Query(value = "{ 'menuParent': ?0 }", sort = "{ 'code': 1 }")
    List<Menu> getDatableSubMenusByParentCode(String menuParent);

    List<Menu> findAllByCodeIn(List<String> menuCodes);

}