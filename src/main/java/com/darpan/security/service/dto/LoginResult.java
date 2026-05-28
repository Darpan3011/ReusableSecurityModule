package com.darpan.security.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Represents the outcome of a login attempt.
 * Instead of throwing exceptions with encoded strings,
 * the service returns one of three states:
 * SUCCESS, MFA_REQUIRED, or EMAIL_NOT_VERIFIED.
 */
@Getter
@AllArgsConstructor
public class LoginResult {

    public enum Status {
        SUCCESS,
        MFA_REQUIRED,
        EMAIL_NOT_VERIFIED
    }

    private final Status status;
    private final AuthResponse authResponse;           // non-null when SUCCESS
    private final MfaRequiredResponse mfaResponse;     // non-null when MFA_REQUIRED
    private final Long userId;                         // non-null when EMAIL_NOT_VERIFIED

    public static LoginResult success(AuthResponse authResponse) {
        return new LoginResult(Status.SUCCESS, authResponse, null, null);
    }

    public static LoginResult mfaRequired(MfaRequiredResponse mfaResponse) {
        return new LoginResult(Status.MFA_REQUIRED, null, mfaResponse, null);
    }

    public static LoginResult emailNotVerified(Long userId) {
        return new LoginResult(Status.EMAIL_NOT_VERIFIED, null, null, userId);
    }
}
