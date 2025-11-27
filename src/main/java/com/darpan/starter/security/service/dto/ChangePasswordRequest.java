package com.darpan.starter.security.service.dto;

import lombok.*;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Getter
@Setter
@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class ChangePasswordRequest {

    @Email
    @NotBlank
    private String email;

    @NotBlank
    private String currentPassword;

    @NotBlank @Size(min = 8, message = "password must be at least 8 characters")
    private String newPassword;
}
