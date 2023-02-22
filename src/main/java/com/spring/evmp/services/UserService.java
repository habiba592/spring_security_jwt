package com.spring.evmp.services;

import com.spring.evmp.models.ERole;
import com.spring.evmp.models.Role;
import com.spring.evmp.models.User;
import com.spring.evmp.payload.request.LoginRequest;
import com.spring.evmp.payload.request.SignupRequest;
import com.spring.evmp.payload.response.MessageResponse;
import com.spring.evmp.payload.response.UserInfoResponse;
import com.spring.evmp.repository.RoleRepository;
import com.spring.evmp.repository.UserRepository;
import com.spring.evmp.security.jwt.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Value("${com.spring.jwtSecret}")
    private String jwtSecret;


    public UserInfoResponse signInUser(LoginRequest loginRequest){
        // Authenticate user and password to get role from the database
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        String jwtToken = jwtUtils.generateJwtToken(userDetails, roles);
        final String token= String.valueOf(jwtToken);

        return new UserInfoResponse(userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles,token);
    }

    public ResponseEntity signUp(SignupRequest signupRequest)
    {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.
                    badRequest().
                    body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.
                    badRequest().
                    body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "hr":
                        Role modRole = roleRepository.findByName(ERole.HR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);
        return  ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }


    public List<User> getAllAdminUsers(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("ADMIN")) {
                List<User> userData = getAllUsers();
                return userData;
            }
        }
        // If the user doesn't have the required role, return a 403 Forbidden response
        throw new AccessDeniedException("You don't have permission to access this resource");
    }

    public List<User> getAllUsers() {

        return userRepository.findAll();
    }

    public List<User> getAllHRUsers(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("HR")) {
                List<User> hrUsers = userRepository.findByRoles("HR");
                return hrUsers;
            }
        }
        // If the user doesn't have the required role, return a 403 Forbidden response
        throw new AccessDeniedException("You don't have permission to access this resource");
    }

  /*  public List<User> getAllHRUsers(List<User> hrusers) {

        List<User> hrUsers=userRepository.findByRoles(hrusers);
        return hrUsers;
    }*/


}

