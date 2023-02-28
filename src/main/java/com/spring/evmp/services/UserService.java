package com.spring.evmp.services;

import com.spring.evmp.dto.CompanyDTO;
import com.spring.evmp.dto.PermissionDto;
import com.spring.evmp.dto.RoleDto;
import com.spring.evmp.dto.UserDto;
import com.spring.evmp.exception.BadRequestException;
import com.spring.evmp.exception.ErrorResponse;
import com.spring.evmp.exception.RoleAlreadyExistsException;
import com.spring.evmp.exception.UnauthorizedUserException;
import com.spring.evmp.models.*;
import com.spring.evmp.payload.request.LoginRequest;
import com.spring.evmp.payload.request.SignupRequest;
import com.spring.evmp.payload.response.MessageResponse;
import com.spring.evmp.payload.response.UserInfoResponse;
import com.spring.evmp.repository.CompanyRepositiory;
import com.spring.evmp.repository.PermissionRepository;
import com.spring.evmp.repository.RoleRepository;
import com.spring.evmp.repository.UserRepository;
import com.spring.evmp.security.jwt.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
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
public class UserService  implements UsersService {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PermissionRepository permissionRepository;



    @Autowired
    CompanyRepositiory companyRepositiory;

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
        Company company = new Company(signupRequest.getCompany());
        // Create new user's account
        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()));
        user.setCompany(company);
        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();


        //Roles Set
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(String.valueOf(ERole.MAKER))
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "super_admin":
                        Role adminRole = roleRepository.findByName(String.valueOf(ERole.SUPER_ADMIN))
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "hr":
                        Role modRole = roleRepository.findByName(String.valueOf(ERole.ADMIN))
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(String.valueOf(ERole.APPROVAL))
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return  ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

@Override
public ResponseEntity<?> createUserWithRoles(HttpServletRequest request, UserDto userDto) {
    String authorizationHeader = request.getHeader("Authorization");
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
        String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
        Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
        List<String> roles = (List<String>) claims.get("role");
        if (userRepository.existsByUsername(userDto.getUsername())) {
            return ResponseEntity.
                    badRequest().
                    body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            return ResponseEntity.
                    badRequest().
                    body(new MessageResponse("Error: Email is already in use!"));
        }
        if (roles.contains("super-admin") || roles.contains("super_admin") || roles.contains("SUPER_ADMIN") || roles.contains("SUPER-ADMIN")) {
            // Super admin role, cannot create another super admin
            if (userDto.getRole().contains("super-admin") ||userDto.getRole().contains("super_admin") ||  userDto.getRole().contains("SUPER_ADMIN")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Cannot create super admin user");
            }
        } else if (roles.contains("admin") || roles.contains("ADMIN")) {
            // Admin role, cannot create another admin or super admin
            if (userDto.getRole().contains("admin") || userDto.getRole().contains("ADMIN")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Cannot create admin user");
            } else if (userDto.getRole().contains("super-admin") || userDto.getRole().contains("SUPER-ADMIN")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Cannot create super admin user");
            }
        } else {
            // User does not have super-admin or admin role, return unauthorized error response
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        // Proceed with creating user
        User user = new User();
        user.setUsername(userDto.getUsername());
        user.setPassword(encoder.encode(userDto.getPassword()));
        user.setEmail(userDto.getEmail());
        Set<Role> userRoles = new HashSet<>();
        for (String roleName : userDto.getRole()) {
            Role role = roleRepository.findByName(roleName).get();
            if (role != null) {
                userRoles.add(role);
            }
        }
       Company companyExists = companyRepositiory.findByName(userDto.getCompany());
        Company company = new Company(userDto.getCompany());
        if(companyExists!=null)
        {
            user.setCompany(companyExists);
        }
        user.setRoles(userRoles);
        User savedUser = userRepository.save(user);
        return ResponseEntity.ok(savedUser);
    } else {
        // Authorization header not present in the request, return bad request error response
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }
}




    public ResponseEntity<List<User>> getUsersByRole(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("admin") || roles.contains("ADMIN")) {
                // User has admin role, proceed with getting users
                String roleName = request.getHeader("Role-Name");
                Role role = roleRepository.findByName(roleName).get();
                if (role != null) {
                    List<User> users = userRepository.findByRolesContaining(role);
                    return ResponseEntity.ok(users);
                } else {
                    // Role not found, return not found error response
                    return ResponseEntity.notFound().build();
                }
            } else {
                // User does not have admin role, return unauthorized error response
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } else {
            // Authorization header not present in the request, return bad request error response
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
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



   /* public User createUser(User user) {
        // Check if the current user has the "super admin" role
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean hasSuperAdminRole = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_SUPER_ADMIN"));
        if (!hasSuperAdminRole) {
            throw new AccessDeniedException("You do not have permission to create a new user.");
        }

        // Add the "admin" role to the new user
        Role adminRole = roleRepository.findByName("ROLE_ADMIN");
        user.addRole(adminRole);

        // Encode the user's password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }*/



    @Override
    public  ResponseEntity<?> createPermission(HttpServletRequest request, PermissionDto permissions) {

        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("admin") || roles.contains("ADMIN")|| roles.contains("SUPER_ADMIN")|| roles.contains("super-admin")) {
                Permissions permissions1= new Permissions();
                permissions1.setName(permissions.getName());
                if(permissionRepository.existsByName(permissions1.getName())){
                    return ResponseEntity.
                            badRequest().
                            body(new MessageResponse("Error: Permission is already taken!"));
                }
                Permissions createdPermission = permissionRepository.save(permissions1);
                return ResponseEntity.ok(createdPermission);
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @Override
    public  ResponseEntity<?> createCompany(HttpServletRequest request, CompanyDTO companyDTO) {

        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("admin") || roles.contains("ADMIN")|| roles.contains("SUPER_ADMIN")|| roles.contains("super-admin")) {
                Company company= new Company();
                company.setName(companyDTO.getName());
                if(companyRepositiory.existsByName(company.getName())){
                    return ResponseEntity.
                            badRequest().
                            body(new MessageResponse("Error: Permission is already taken!"));
                }
                Company createdCompany = companyRepositiory.save(company);
                return ResponseEntity.ok(createdCompany);
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @Override
    public List<Permissions> getAllPermissions(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("SUPER_ADMIN") || roles.contains("super-admin")|| roles.contains("admin")|| roles.contains("ADMIN")) {
                // User has admin role, proceed with retrieving all roles
                List<Permissions> permissions = permissionRepository.findAll();
                return permissions;
            } else {
                // User does not have super admin role, return unauthorized error response
                throw new UnauthorizedUserException("User does not have super admin role");
            }
        } else {
            // Authorization header not present in the request, return bad request error response
            throw new BadRequestException(" Authorization header not present in the request");
        }
    }
    @Override
    public ResponseEntity<?> createRole(HttpServletRequest request, RoleDto roleDto) throws RoleAlreadyExistsException, UnauthorizedUserException, BadRequestException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("super-admin") || roles.contains("SUPER_ADMIN") || roles.contains("admin") || roles.contains("ADMIN")) {
                // User has either super-admin or admin role, proceed with creating role
                Role role = new Role();
                String roleName = roleDto.getName().toLowerCase();
                role.setName(roleName);

                // Check if role already exists in the database
                Role existingRole = roleRepository.findByRoleName(roleName);
                if (existingRole != null) {
                    throw new RoleAlreadyExistsException("Role already exists");
                }

                // Check if super-admin role already exists in the database
                if (roleName.equals("super-admin")) {
                    List<Role> superAdminRoles = roleRepository.findByNameIgnoreCase(roleName);
                    if (superAdminRoles != null && !superAdminRoles.isEmpty()) {
                        throw new RoleAlreadyExistsException("Super-admin role already exists");
                    }
                }

                // Check if admin role already exists in the database
                if (roleName.equals("admin")) {
                    List<Role> adminRoles = roleRepository.findByNameIgnoreCase(roleName);
                    if (adminRoles != null && !adminRoles.isEmpty()) {
                        throw new RoleAlreadyExistsException("Admin role already exists");
                    }
                }

                if (roleName.equals("super-admin")) {
                    role.setParent_id(null);
                } else {
                    // If user is creating any other role, set parent id to admin id if user is admin or super admin
                    // Otherwise, return unauthorized error response

                    if (roles.contains("admin") || roles.contains("ADMIN")) {
                        List<String> name = (List<String>) claims.get("role");
                        String roleNamee = name.get(0); // Assuming there's only one role per user
                        int adminId = roleRepository.findByRole(roleNamee);
                        role.setParent_id(adminId);
                    } else if (roles.contains("super-admin") || roles.contains("SUPER_ADMIN")) {
                        List<String> name = (List<String>) claims.get("role");
                        String roleNamee = name.get(0); // Assuming there's only one role per user
                        int adminId = roleRepository.findByRole(roleNamee);
                        role.setParent_id(adminId);
                    } else {
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("User not authorized to create role"));
                    }
                }

                Set<Permissions> permissions = new HashSet<>();
                for (PermissionDto permissionDto : roleDto.getPermissions()) {
                    Permissions permission = permissionRepository.findByName(permissionDto.getName());
                    if (permission != null) {
                        permissions.add(permission);
                    }
                }
                role.setPermissions(permissions);
                Role savedRole = roleRepository.save(role);
                // Save role-permission associations to role_permission table
                for (Permissions permission : permissions) {
                    savedRole.addPermission(permission);
                }
                roleRepository.save(savedRole);

                return ResponseEntity.ok(savedRole);
            } else {
                // User does not have super-admin or admin role, return unauthorized error response
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("User not authorized to create role"));
            }
        } else {
            // Authorization header not present in the request, return bad request error response
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("Authorization header missing"));
        }
    }


    @Override
    public List<Role> getAllRoles(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("SUPER_ADMIN") || roles.contains("super-admin")|| roles.contains("admin")|| roles.contains("ADMIN")) {
                // User has admin role, proceed with retrieving all roles
                List<Role> role = roleRepository.findAll();
                return role;
            } else {
                // User does not have super admin role, return unauthorized error response
                throw new UnauthorizedUserException("User does not have super admin role");
            }
        } else {
            // Authorization header not present in the request, return bad request error response
            throw new BadRequestException(" Authorization header not present in the request");
        }
    }

    @Override
    public List<Company> getAllCompany(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("SUPER_ADMIN") || roles.contains("super-admin")|| roles.contains("admin")|| roles.contains("ADMIN")) {
                // User has admin role, proceed with retrieving all roles
                List<Company> companies = companyRepositiory.findAll();
                return companies;
            } else {
                // User does not have super admin role, return unauthorized error response
                throw new UnauthorizedUserException("User does not have super admin role");
            }
        } else {
            // Authorization header not present in the request, return bad request error response
            throw new BadRequestException(" Authorization header not present in the request");
        }
    }



    public List<User> getAllUsers(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token from the "Bearer " prefix
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            List<String> roles = (List<String>) claims.get("role");
            if (roles.contains("SUPER_ADMIN") || roles.contains("super-admin")) {
                // User has admin role, proceed with retrieving all roles
                List<User> users = userRepository.findAll();
                return users;
            } else {
                // User does not have super admin role, return unauthorized error response
                 throw new UnauthorizedUserException("User does not have super admin role");
            }
        } else {
            // Authorization header not present in the request, return bad request error response
             throw new BadRequestException(" Authorization header not present in the request");
        }
    }


}

