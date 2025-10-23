package com.darpan.starter.security.serviceimpl;

import com.darpan.starter.security.repository.TokenRepository;
import com.darpan.starter.security.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepo;

    @Override
    public boolean isTokenPresentInDB(String token) {
        return tokenRepo.existsByAccessToken(token);
    }
}
