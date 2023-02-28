package com.spring.evmp.repository;

import java.util.List;
import java.util.Optional;

import com.spring.evmp.models.ERole;
import com.spring.evmp.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(String name);

  @Query(value = "SELECT id FROM role WHERE name = 'SUPER_ADMIN'", nativeQuery = true)
  int findSuperAdminId();

  List<Role> findByNameIgnoreCase(String name);

  @Query(value = "SELECT name FROM role WHERE name =:name", nativeQuery = true)
  Role findByRoleName(String name);

  @Query(value = "SELECT id FROM role WHERE name  = :name", nativeQuery = true)
  int findByRole(@Param("name") String name);



}
