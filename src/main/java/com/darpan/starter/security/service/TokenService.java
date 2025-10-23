package com.darpan.starter.security.service;

public interface TokenService {

    boolean isTokenPresentInDB(String token);
}
