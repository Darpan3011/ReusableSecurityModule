package com.darpan.starter.security.repository;

import com.darpan.starter.security.model.MfaCode;
import com.darpan.starter.security.model.MfaCodeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface MfaCodeRepository extends JpaRepository<MfaCode, Long> {

    Optional<MfaCode> findByUserIdAndTypeAndVerifiedFalse(Long userId, MfaCodeType type);

    void deleteByUserId(Long userId);

    void deleteByExpiresAtBefore(LocalDateTime dateTime);
}
