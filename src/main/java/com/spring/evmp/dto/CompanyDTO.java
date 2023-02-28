package com.spring.evmp.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CompanyDTO {
    private String name;

    public CompanyDTO() {}

    public CompanyDTO(String name) {
        this.name = name;
    }
}
