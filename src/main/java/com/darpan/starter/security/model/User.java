package com.darpan.starter.security.model;

import com.darpan.starter.security.service.enums.MfaDeliveryMethod;
import jakarta.persistence.*;
import lombok.*;
import net.minidev.json.annotate.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users", indexes = { @Index(columnList = "username", unique = true) })
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

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
    
    // MFA fields
    @Column(nullable = false)
    private boolean mfaEnabled = false;
    
    @Column(nullable = false)
    private boolean emailVerified = false;
    
    // Phone number and SMS MFA fields
    @Column(nullable = true)
    private String phoneNumber;
    
    @Column(nullable = false)
    private boolean phoneNumberVerified = false;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private MfaDeliveryMethod mfaDeliveryMethod = MfaDeliveryMethod.EMAIL;
    
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).toList();
    }
    @Override public String getPassword(){ return password; }
    @Override public String getUsername(){ return username; }
    @Override public boolean isAccountNonExpired() { return accountNonExpired; }
    @Override public boolean isAccountNonLocked() { return accountNonLocked; }
    @Override public boolean isCredentialsNonExpired() { return credentialsNonExpired; }
    @Override public boolean isEnabled() { return enabled; }
}
