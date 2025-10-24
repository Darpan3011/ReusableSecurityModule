package com.darpan.starter.security.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "tokens", indexes = { @Index(columnList = "refreshToken", unique = true) })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    @Column(length = 2000)
    private String accessToken;

    @Column(length = 2000, unique = true)
    private String refreshToken;

    private Instant accessTokenExpiry;
    private Instant refreshTokenExpiry;

    private Instant createdAt;
    private boolean active = true;

    @PrePersist
    public void onCreate() {
        this.createdAt = Instant.now();
    }

}
