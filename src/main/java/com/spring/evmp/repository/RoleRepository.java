package com.spring.evmp.repository;

import java.util.Optional;

import com.spring.evmp.models.ERole;
import com.spring.evmp.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
