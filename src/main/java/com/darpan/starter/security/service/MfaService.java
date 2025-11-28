package com.darpan.starter.security.service;

import com.darpan.starter.security.model.MfaCodeType;

public interface MfaService {

    /**
     * Generate a new MFA code and send it via email
     * @param userId User ID
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     */
    void generateAndSendCode(Long userId, MfaCodeType type);

    /**
     * Generate a new MFA code and send it via email (with User object)
     * @param user User object
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     */
    void generateAndSendCodeWithUser(com.darpan.starter.security.model.User user, MfaCodeType type);

    /**
     * Verify the MFA code
     * @param userId User ID
     * @param code The 6-digit code
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     * @return true if code is valid and not expired
     */
    boolean verifyCode(Long userId, String code, MfaCodeType type);

    /**
     * Resend the MFA code (generates new code if expired)
     * @param userId User ID
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     */
    void resendCode(Long userId, MfaCodeType type);

    /**
     * Toggle MFA for a user
     * @param userId User ID
     * @param enabled Enable or disable MFA
     */
    void toggleMfa(Long userId, boolean enabled);

    /**
     * Clean up expired codes (scheduled task)
     */
    void cleanupExpiredCodes();
}
