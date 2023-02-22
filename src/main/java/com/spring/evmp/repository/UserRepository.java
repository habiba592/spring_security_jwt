package com.spring.evmp.repository;

import java.util.List;
import java.util.Optional;

import com.spring.evmp.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);

  /*List<User> findBy(List<String> roles);*/
  @Query(nativeQuery = true, value = "SELECT * FROM user as u \n" +
          "INNER JOIN users_roles as ur on u.id=ur.user_id\n" +
          "INNER JOIN role as r on ur.role_id=r.id\n" +
          "where r.name = :role")
  List<User> findByRoles(@Param("role") String role);



}
