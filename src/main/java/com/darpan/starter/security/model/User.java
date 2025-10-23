package com.darpan.starter.security.model;

import jakarta.persistence.*;
import java.util.Collection;
import java.util.Collections;

import lombok.*;
import net.minidev.json.annotate.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class User implements UserDetails {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank @Column(unique = true, nullable = false)
    private String username;

    @Email
    @NotBlank @Column(unique = true, nullable = false)
    private String email;

    @NotBlank
    @JsonIgnore
    private String password;

    private String firstName;
    private String lastName;

    // UserDetails
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }
    @Override public String getPassword(){ return password; }
    @Override public String getUsername(){ return username; }
    @Override public boolean isAccountNonExpired(){ return true; }
    @Override public boolean isAccountNonLocked(){ return true; }
    @Override public boolean isCredentialsNonExpired(){ return true; }
    @Override public boolean isEnabled(){ return true; }
}
