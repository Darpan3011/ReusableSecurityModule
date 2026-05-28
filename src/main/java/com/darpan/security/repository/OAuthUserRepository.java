package com.darpan.security.repository;

import com.darpan.security.model.OAuthUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuthUserRepository extends JpaRepository<OAuthUser, Long> {
    Optional<OAuthUser> findByProviderAndProviderUserId(String provider, String providerUserId);
}
