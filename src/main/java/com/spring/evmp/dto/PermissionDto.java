package com.spring.evmp.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PermissionDto {

    private String name;

    public PermissionDto() {}

    public PermissionDto(String name) {
        this.name = name;
    }

}