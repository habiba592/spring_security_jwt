package com.spring.evmp.controllers;

import com.spring.evmp.dto.CompanyDTO;
import com.spring.evmp.dto.PermissionDto;
import com.spring.evmp.dto.RoleDto;
import com.spring.evmp.dto.UserDto;
import com.spring.evmp.exception.*;
import com.spring.evmp.models.Company;
import com.spring.evmp.models.Permissions;
import com.spring.evmp.models.Role;
import com.spring.evmp.models.User;
import com.spring.evmp.payload.response.MessageResponse;
import com.spring.evmp.payload.response.UserDataResponse;
import com.spring.evmp.services.UserService;
import com.spring.evmp.services.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

  @Autowired
  UserService userService;

  @Autowired
  UsersService usersService;

  @GetMapping("/hr")
  public ResponseEntity<?> getUserDataAcessToHR(HttpServletRequest httpServletRequest) {
    try {
      List<User> users = userService.getAllHRUsers(httpServletRequest);
      if (users == null) {
        // Return a 404 Not Found response if no users were found
        return ResponseEntity.notFound().build();
      }
      UserDataResponse response = new UserDataResponse(users);
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      // Return a 500 Internal Server Error response with a message
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("An error occurred while fetching user data. Please try again later."));
    }
  }

  @PostMapping("/createUser")
  public ResponseEntity<?> createUserWithRoles(HttpServletRequest httpServletRequest,@RequestBody UserDto userDto) {
    ResponseEntity<?> response;
    try {
      response = usersService.createUserWithRoles(httpServletRequest, userDto);
    } catch (RoleAlreadyExistsException e) {
      response = ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("Role Already Exists"));
    } catch (UnauthorizedUserException e) {
      response = ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Unauthorized User"));
    } catch (BadRequestException e) {
      response = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("Bad Request"));
    }
    catch (ForbiddenUserException e) {
      response = ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse("Forbidden User"));
    }
    return response;
  }



  @PostMapping("/createRole")
  public ResponseEntity<?> createRole(HttpServletRequest httpServletRequest,@RequestBody RoleDto roleDto) {
    ResponseEntity<?> response;
    try {
      response = usersService.createRole(httpServletRequest, roleDto);
    } catch (RoleAlreadyExistsException e) {
      response = ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("Role Already Exists"));
    } catch (UnauthorizedUserException e) {
      response = ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Unauthorized Role"));
    } catch (BadRequestException e) {
      response = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("Bad Request"));
    }
    catch (ForbiddenUserException e) {
      response = ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse("Forbidden Role"));
    }
    return response;
  }


  @GetMapping("/getAllUsers")
  public ResponseEntity<?> getAllUsersAccessBySuperAdmin(HttpServletRequest httpServletRequest) {

    try {
      List<User> users = userService.getAllUsers(httpServletRequest);
      if (users == null) {
        // Return a 404 Not Found response if no users were found
        return ResponseEntity.notFound().build();
      }
      UserDataResponse response = new UserDataResponse(users);
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      // Return a 500 Internal Server Error response with a message
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("An error occurred while fetching user data. Please try again later."));
    }
  }

  //Get All ROles

  @GetMapping("/getAllRoles")
  public ResponseEntity<?> getAllRoles(HttpServletRequest httpServletRequest) {

    try {
      List<Role> roles = userService.getAllRoles(httpServletRequest);
      if (roles == null) {
        // Return a 404 Not Found response if no users were found
        return ResponseEntity.notFound().build();
      }
      UserDataResponse response = new UserDataResponse(roles);
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      // Return a 500 Internal Server Error response with a message
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("An error occurred while fetching user data. Please try again later."));
    }
  }

//Create Permission
  @PostMapping("/createPermissions")
  public ResponseEntity<?> createPermissions(HttpServletRequest httpServletRequest,@RequestBody PermissionDto permissionDto) {
    ResponseEntity<?> response;
    try {
      response = usersService.createPermission(httpServletRequest, permissionDto);
    } catch (RoleAlreadyExistsException e) {
      response = ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("Permission Already Exists"));
    } catch (UnauthorizedUserException e) {
      response = ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Unauthorized Permission"));
    } catch (BadRequestException e) {
      response = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("Bad Request"));
    }
    catch (ForbiddenUserException e) {
      response = ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse("Forbidden Permission"));
    }
    return response;
  }

  //Create Comapny
  @PostMapping("/createCompany")
  public ResponseEntity<?> createCompany(HttpServletRequest httpServletRequest,@RequestBody CompanyDTO companyDTO) {
    ResponseEntity<?> response;
    try {
      response = usersService.createCompany(httpServletRequest, companyDTO);
    } catch (RoleAlreadyExistsException e) {
      response = ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("Comapny is Already Exists"));
    } catch (UnauthorizedUserException e) {
      response = ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("Unauthorized Permission"));
    } catch (BadRequestException e) {
      response = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("Bad Request"));
    }
    catch (ForbiddenUserException e) {
      response = ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse("Forbidden Permission"));
    }
    return response;
  }


  //Get All ROles

  @GetMapping("/getAllCompany")
  public ResponseEntity<?> getAllCompany(HttpServletRequest httpServletRequest) {

    try {
      List<Company> companies = userService.getAllCompany(httpServletRequest);
      if (companies == null) {
        // Return a 404 Not Found response if no users were found
        return ResponseEntity.notFound().build();
      }
      UserDataResponse response = new UserDataResponse(companies);
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      // Return a 500 Internal Server Error response with a message
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("An error occurred while fetching user data. Please try again later."));
    }
  }

  @GetMapping("/getAllPermission")
  public ResponseEntity<?> getAllPermissions(HttpServletRequest httpServletRequest) {

    try {
      List<Permissions> permissions = userService.getAllPermissions(httpServletRequest);
      if (permissions == null) {
        // Return a 404 Not Found response if no users were found
        return ResponseEntity.notFound().build();
      }
      UserDataResponse response = new UserDataResponse(permissions);
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      // Return a 500 Internal Server Error response with a message
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("An error occurred while fetching user data. Please try again later."));
    }
  }
}
