package com.darpan.security.service;

import com.darpan.security.model.User;
import com.darpan.security.service.dto.AuthResponse;
import com.darpan.security.service.dto.PhoneStatusResponse;
import com.darpan.security.service.enums.MfaCodeType;
import com.darpan.security.service.enums.MfaDeliveryMethod;

public interface MfaService {

    /**
     * Generate a new MFA code and send it via email
     * @param userId User ID
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     */
    void generateAndSendCode(Long userId, MfaCodeType type);

    /**
     * Generate a new MFA code and send it via specified method
     * @param userId User ID
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     * @param method Delivery method (EMAIL or SMS)
     */
    void generateAndSendCode(Long userId, MfaCodeType type, MfaDeliveryMethod method);

    /**
     * Generate a new MFA code and send it via email (with User object)
     * @param user User object
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     */
    void generateAndSendCodeWithUser(User user, MfaCodeType type);

    /**
     * Verify the MFA code
     * @param userId User ID
     * @param code The 6-digit code
     * @param type Type of MFA code (REGISTRATION or LOGIN)
     * @return true if code is valid and not expired
     */
    boolean verifyCode(Long userId, String code, MfaCodeType type);

    /**
     * Verify email code and activate user account
     * @param userId User ID
     * @param code The 6-digit code
     * @return true if verification successful
     */
    boolean verifyEmailAndActivate(Long userId, String code);

    /**
     * Verify MFA code and generate authentication tokens
     * @param userId User ID
     * @param code The 6-digit code
     * @return AuthResponse with tokens
     */
    AuthResponse verifyMfaAndGenerateTokens(Long userId, String code);

    /**
     * Toggle MFA for a user by username
     * @param username Username
     * @param enabled Enable or disable MFA
     */
    void toggleMfaForUser(String username, boolean enabled);

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

    /**
     * Set or update user's phone number and send verification code
     * @param userId User ID
     * @param phoneNumber Phone number to set
     */
    void setPhoneNumber(Long userId, String phoneNumber);

    /**
     * Verify phone number with code
     * @param userId User ID
     * @param code Verification code
     * @return true if verification successful
     */
    boolean verifyPhoneNumber(Long userId, String code);





    /**
     * Set or update user's phone number and send verification code (by username)
     * @param username Username
     * @param phoneNumber Phone number to set
     */
    void setPhoneNumberByUsername(String username, String phoneNumber);

    /**
     * Verify phone number with code (by username)
     * @param username Username
     * @param code Verification code
     * @return true if verification successful
     */
    boolean verifyPhoneNumberByUsername(String username, String code);



    /**
     * Get phone status for user (by username)
     * @param username Username
     * @return Phone status response
     */
    PhoneStatusResponse getPhoneStatusByUsername(String username);
}
