package com.darpan.starter.security.repository;

import com.darpan.starter.security.model.OAuthSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

//@Repository
public interface OAuthSessionRepository extends JpaRepository<OAuthSession, Long> {
    Optional<OAuthSession> findBySessionId(String sessionId);
}

