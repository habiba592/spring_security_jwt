package com.spring.evmp.models;

import jdk.nashorn.internal.objects.annotations.Constructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "company",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "name")
        })
@Getter
@Setter

public class Company {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name")
    private String name;
    public Company(String name) {
        this.name = name;
    }


    public Company(Company company) {
    }

    public Company() {

    }
}