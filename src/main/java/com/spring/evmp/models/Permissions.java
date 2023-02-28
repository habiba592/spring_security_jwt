package com.spring.evmp.models;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "permissions",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "name")
        })
@Getter
@Setter
public class Permissions {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(length = 20)
    private String name;

    public Permissions() {
    }

}