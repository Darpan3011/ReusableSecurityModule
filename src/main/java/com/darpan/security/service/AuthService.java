package com.darpan.security.service;

import com.darpan.security.model.User;
import com.darpan.security.service.dto.AuthResponse;
import com.darpan.security.service.dto.ChangePasswordRequest;
import com.darpan.security.service.dto.LoginRequest;
import com.darpan.security.service.dto.RegisterRequest;
import com.darpan.security.service.enums.AuthEnum;

public interface AuthService {
    /**
     * Register a new user
     * @param req Registration request containing user details
     * @return Registered User object
     */
    User register(RegisterRequest req);

    /**
     * Authenticate a user and generate tokens
     * @param req Login request containing credentials
     * @return AuthResponse containing JWT tokens
     */
    AuthResponse login(LoginRequest req);

    /**
     * Refresh access token using a refresh token
     * @param refreshToken Valid refresh token
     * @return AuthResponse containing new access token
     */
    AuthResponse refresh(String refreshToken);

    /**
     * Find a user by their username
     * @param username Username to search for
     * @return User object found
     */
    User findByUsername(String username);

    /**
     * Change the password for the current user
     * @param request Change password request containing old and new passwords
     */
    void changePassword(ChangePasswordRequest request);

    /**
     * Get the authentication type (e.g., JWT, OAUTH2)
     * @return AuthEnum representing the authentication type
     */
    AuthEnum getAuthType();

    /**
     * Initiate password reset process by sending a code to the email
     * @param email Email address of the user
     */
    void forgotPassword(String email);

    /**
     * Reset password using the verification code
     * @param email Email address of the user
     * @param code Verification code sent to email
     * @param newPassword New password to set
     */
    void resetPassword(String email, String code, String newPassword);
}
