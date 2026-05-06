package com.jwt.authentication.repository;

import com.jwt.authentication.models.ERole;
import com.jwt.authentication.models.Menu;
import com.jwt.authentication.models.Role;
import org.springframework.data.mongodb.repository.Aggregation;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface  RoleRepository extends  MongoRepository<Role,String> {
    Optional<Role> findByName(ERole eRole);
    List<Role> findAllByCodeIn(List<String> codes);

    //pipline เริ่มที่ role ต้องเอามาไว้ที่นี่
    @Aggregation(pipeline = {
            // 1. match roles ของ user
            "{ $match: { code: { $in: ?0 } } }",

            // 2. join permissions (filter enabled = true)
            "{ $lookup: { " +
                    "from: 'permissions', " +
                    "let: { roleCode: '$code' }, " +
                    "pipeline: [ " +
                    "{ $match: { $expr: { $and: [ " +
                    "{ $eq: ['$roleCode', '$$roleCode'] }, " +
                    "{ $eq: ['$enabled', true] } " +
                    "] } } } " +
                    "], " +
                    "as: 'permissions' " +
                    "} }",

            // 3. unwind permissions
            "{ $unwind: '$permissions' }",

            // 4. join menus
            "{ $lookup: { " +
                    "from: 'menus', " +
                    "localField: 'permissions.menuCode', " +
                    "foreignField: 'code', " +
                    "as: 'menu' " +
                    "} }",

            // 5. unwind menu
            "{ $unwind: '$menu' }",

            // 6. filter menu
            "{ $match: { " +
                    "'menu.status': 'ACTIVE', " +
                    "'menu.groupCode': 'MANAGEMENT', " +
                  //  "'menu.menuParent': { $ne: '00' } " +
                    "} }",

            // 7. replace root เป็น menu
            "{ $replaceRoot: { newRoot: '$menu' } }",

            // 8. distinct by code (dedup)
            "{ $group: { _id: '$code', doc: { $first: '$$ROOT' } } }",

            // 9. unwrap
            "{ $replaceRoot: { newRoot: '$doc' } }",

            // 10. sort
            "{ $sort: { code: 1 } }"

    })
    List<Menu> findMenusByRoles(List<String> roleCodes);
}
