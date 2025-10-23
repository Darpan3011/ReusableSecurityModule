package com.darpan.starter.security.serviceimpl;

import com.darpan.starter.security.jwt.JwtTokenProvider;
import com.darpan.starter.security.model.Token;
import com.darpan.starter.security.model.User;
import com.darpan.starter.security.repository.TokenRepository;
import com.darpan.starter.security.repository.UserRepository;
import com.darpan.starter.security.service.AuthService;
import com.darpan.starter.security.service.dto.AuthResponse;
import com.darpan.starter.security.service.dto.LoginRequest;
import com.darpan.starter.security.service.dto.RegisterRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.Optional;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepo;
    private final TokenRepository tokenRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;

    public AuthServiceImpl(UserRepository userRepo, TokenRepository tokenRepo, PasswordEncoder passwordEncoder, JwtTokenProvider tokenProvider) {
        this.userRepo = userRepo;
        this.tokenRepo = tokenRepo;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
    }

    @Override
    @Transactional
    public User register(RegisterRequest req) {
        User u = new User();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPassword(passwordEncoder.encode(req.getPassword()));
        return userRepo.save(u);
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest req) {
        Optional<User> userOpt = userRepo.findByUsername(req.getUsername());
        if (userOpt.isEmpty()) throw new RuntimeException("Invalid credentials");
        User user = userOpt.get();
        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) throw new RuntimeException("Invalid credentials");

        String access = tokenProvider.generateAccessToken(user.getUsername(), user.getId());
        String refresh = tokenProvider.generateRefreshToken(user.getUsername(), user.getId());

        Token token = new Token();
        token.setUserId(user.getId());
        token.setAccessToken(access);
        token.setRefreshToken(refresh);
        token.setAccessTokenExpiry(Instant.now().plusMillis(tokenProvider.getAccessExpiryMillis()));
        token.setRefreshTokenExpiry(Instant.now().plusMillis(tokenProvider.getRefreshExpiryMillis()));
        tokenRepo.save(token);

        return new AuthResponse(access, refresh, tokenProvider.getAccessExpiryMillis()/1000);
    }

    @Override
    @Transactional
    public AuthResponse refresh(String refreshToken) {
        Token token = tokenRepo.findByRefreshToken(refreshToken).orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        if (!tokenProvider.validateToken(refreshToken)) {
            tokenRepo.delete(token);
            throw new RuntimeException("Expired refresh token");
        }
        // parse username from refresh token using provider's configured key
        String username = tokenProvider.getUsername(refreshToken);
        Long uid = token.getUserId();
        String newAccess = tokenProvider.generateAccessToken(username, uid);
        token.setAccessToken(newAccess);
        token.setAccessTokenExpiry(Instant.now().plusMillis(tokenProvider.getAccessExpiryMillis()));
        Token token1 = tokenRepo.save(token);
        log.error("SAved token: {}", token1.getRefreshToken());
        return new AuthResponse(newAccess, refreshToken, tokenProvider.getAccessExpiryMillis()/1000);
    }

    // removed empty key method; provider is the single source for JWT parsing

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepo.findByUsername(username);
    }
}
