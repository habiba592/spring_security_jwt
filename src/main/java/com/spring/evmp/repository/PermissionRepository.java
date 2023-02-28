package com.spring.evmp.repository;
import com.spring.evmp.models.EPermission;
import com.spring.evmp.models.Permissions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.security.acl.Permission;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permissions, Long> {

    Permissions findByName(String name);

    Boolean existsByName(String username);
}
