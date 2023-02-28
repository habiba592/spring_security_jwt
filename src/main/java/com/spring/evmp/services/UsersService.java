package com.spring.evmp.services;

import com.spring.evmp.dto.CompanyDTO;
import com.spring.evmp.dto.PermissionDto;
import com.spring.evmp.dto.RoleDto;
import com.spring.evmp.dto.UserDto;
import com.spring.evmp.models.Company;
import com.spring.evmp.models.Permissions;
import com.spring.evmp.models.Role;
import com.spring.evmp.models.User;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

public interface UsersService {
   /* User createUser(User user);

    User findUserByUsername(String username);

    Role findRoleByName(String name);*/

    ResponseEntity<?> createCompany(HttpServletRequest request, CompanyDTO companyDTO);

    List<Company>  getAllCompany(HttpServletRequest request);

    ResponseEntity<?> createPermission(HttpServletRequest request, PermissionDto permissions);

    List<Permissions> getAllPermissions(HttpServletRequest request);

    List<Role>  getAllRoles(HttpServletRequest request);

    ResponseEntity<?> createUserWithRoles(HttpServletRequest request, UserDto userDto);
    ResponseEntity<?> createRole(HttpServletRequest request, RoleDto roleDto);

    List<User> getAllUsers(HttpServletRequest request);

}
