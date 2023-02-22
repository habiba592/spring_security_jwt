package com.spring.evmp.controllers;

import com.spring.evmp.models.User;
import com.spring.evmp.payload.response.MessageResponse;
import com.spring.evmp.payload.response.UserDataResponse;
import com.spring.evmp.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @Autowired
    UserService userService;
    @GetMapping("/admin")
    public ResponseEntity<?> getUserData(HttpServletRequest httpServletRequest) {
        try {
            List<User> users = userService.getAllAdminUsers(httpServletRequest);
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

    //Update User

 /*    @PostMapping("//update")
  public ResponseEntity<UserData> updateUserData(@RequestBody UserData userData) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    boolean hasAdminRole = authentication.getAuthorities().stream()
            .anyMatch(authority -> authority.getAuthority().equals("ADMIN"));
    if (hasAdminRole) {
      // User has the ADMIN role, so update the data.
      // ...
      return ResponseEntity.ok(userData);
    } else {
      // User does not have the required role, so return an error response.
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
  }*/

}
