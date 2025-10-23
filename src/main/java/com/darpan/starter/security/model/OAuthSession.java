package com.darpan.starter.security.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "oauth_sessions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OAuthSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sessionId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private OAuthUser user;

    private Instant loginTime;

    private Instant logoutTime;

    private String ipAddress;

    private String userAgent;
}

