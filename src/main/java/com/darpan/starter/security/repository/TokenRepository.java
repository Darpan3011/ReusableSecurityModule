package com.darpan.starter.security.repository;

import com.darpan.starter.security.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByRefreshToken(String refreshToken);
    void deleteByRefreshToken(String refreshToken);
    Optional<Boolean> findByAccessToken(String token);
    boolean existsByAccessToken(String token);
}
