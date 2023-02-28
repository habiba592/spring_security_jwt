package com.spring.evmp.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class RoleDto {

    private String name;
    private Set<PermissionDto> permissions;

}