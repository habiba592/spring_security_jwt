package com.spring.evmp.repository;

import com.spring.evmp.models.Company;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CompanyRepositiory extends JpaRepository<Company, Long> {
    Company findByName(String  name);


    Boolean existsByName(String username);
}
