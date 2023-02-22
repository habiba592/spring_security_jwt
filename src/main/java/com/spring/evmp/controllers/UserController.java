package com.spring.evmp.controllers;

import com.spring.evmp.models.User;
import com.spring.evmp.payload.response.MessageResponse;
import com.spring.evmp.payload.response.UserDataResponse;
import com.spring.evmp.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

  @Autowired
  UserService userService;

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






}
