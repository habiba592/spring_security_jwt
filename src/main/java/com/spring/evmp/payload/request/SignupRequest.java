package com.spring.evmp.payload.request;

import com.spring.evmp.models.Company;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

import javax.validation.constraints.*;

@Getter
@Setter
public class SignupRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;
 
    @NotBlank
    @Size(max = 50)
    @Email
    private String email;
    
    private Set<String> role;

    private Company company;
    
    @NotBlank
    @Size(min = 6, max = 40)
    private String password;

}
