package com.darpan.starter.security.service.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private long expiresInSeconds;
}
