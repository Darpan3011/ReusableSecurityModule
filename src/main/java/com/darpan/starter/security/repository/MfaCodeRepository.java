package com.darpan.starter.security.repository;

import com.darpan.starter.security.model.MfaCode;
import com.darpan.starter.security.model.MfaCodeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface MfaCodeRepository extends JpaRepository<MfaCode, Long> {

    Optional<MfaCode> findByUserIdAndTypeAndVerifiedFalse(Long userId, MfaCodeType type);

    @Modifying
    @Transactional
    void deleteByUserIdAndTypeAndVerifiedFalse(Long userId, MfaCodeType type);

    @Modifying
    @Transactional
    void deleteByUserId(Long userId);

    @Modifying
    @Transactional
    void deleteByExpiresAtBefore(LocalDateTime dateTime);
}
