package com.spring.evmp.controllers;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import com.spring.evmp.services.UserService;
import com.spring.evmp.models.ERole;
import com.spring.evmp.models.Role;
import com.spring.evmp.models.User;
import com.spring.evmp.payload.request.LoginRequest;
import com.spring.evmp.payload.request.SignupRequest;
import com.spring.evmp.payload.response.MessageResponse;
import com.spring.evmp.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.evmp.repository.RoleRepository;
import com.spring.evmp.repository.UserRepository;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

  @Autowired
  UserService userService;
  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    return ResponseEntity.ok()
        .body(userService.signInUser(loginRequest));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    userService.signUp(signUpRequest);
    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }


}
