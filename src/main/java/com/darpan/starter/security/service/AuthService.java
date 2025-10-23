package com.darpan.starter.security.service;

import com.darpan.starter.security.model.User;
import com.darpan.starter.security.service.dto.AuthResponse;
import com.darpan.starter.security.service.dto.LoginRequest;
import com.darpan.starter.security.service.dto.RegisterRequest;

import java.util.Optional;

public interface AuthService {
    User register(RegisterRequest req);
    AuthResponse login(LoginRequest req);
    AuthResponse refresh(String refreshToken);
    Optional<User> findByUsername(String username);
}
