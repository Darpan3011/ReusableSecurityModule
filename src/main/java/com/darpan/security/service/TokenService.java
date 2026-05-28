package com.darpan.security.service;

public interface TokenService {

    /**
     * Check if a token exists in the database
     * @param token JWT token string
     * @return true if token exists, false otherwise
     */
    boolean isTokenPresentInDB(String token);
}
