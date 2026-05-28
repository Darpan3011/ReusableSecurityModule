package com.darpan.security.service.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PhoneStatusResponse {
    private String phoneNumber; // Masked, e.g., "***-***-1234"
    private boolean phoneNumberVerified;

    private boolean mfaEnabled;
}
