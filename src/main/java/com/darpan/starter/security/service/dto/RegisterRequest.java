package com.darpan.starter.security.service.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class RegisterRequest {
    private String username;
    private String email;
    private String password;
}
