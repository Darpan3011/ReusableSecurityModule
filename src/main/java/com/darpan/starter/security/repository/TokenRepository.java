package com.darpan.starter.security.repository;

import com.darpan.starter.security.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByRefreshToken(String refreshToken);
    void deleteByRefreshToken(String refreshToken);
    Optional<Boolean> findByAccessToken(String token);
    boolean existsByAccessToken(String token);

    @Modifying
    @Query("UPDATE Token t SET t.active = false WHERE t.userId = :userId AND t.active = true")
    void deactivateOldTokens(Long userId);

    @Modifying
    @Query("DELETE FROM Token t WHERE t.userId = :userId")
    void deleteByUserId(Long userId);
}
