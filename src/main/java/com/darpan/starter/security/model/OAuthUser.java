package com.darpan.starter.security.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

@Entity
@Table(name = "oauth_users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class OAuthUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable=false)
    private String provider;          // "github"
    @Column(nullable=false, unique=true)
    private String providerUserId; // GitHub id as String
    @Column(nullable=false)
    private String username;          // GitHub login
    private String name;
    private String email;             // may be null
    private String avatarUrl;
    private OffsetDateTime lastAccess;
}
