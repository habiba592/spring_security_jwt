package com.spring.evmp.models;
import lombok.Getter;
import lombok.Setter;
import javax.persistence.*;
import javax.validation.constraints.Max;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.security.acl.Permission;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "role",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "name")
        })
@Getter
@Setter
public class Role {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;


  @Column(length = 20)
  private String name;
  @NotNull
  @Max(120)
  private Integer parent_id;



  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
          name = "roles_permissions",
          joinColumns = @JoinColumn(name = "role_id"),
          inverseJoinColumns = @JoinColumn(name = "permission_id")
  )
  private Set<Permissions> permissions = new HashSet<>();

  public Role() {

  }

  public void addPermission(Permissions permission) {
    permissions.add(permission);
  }


}