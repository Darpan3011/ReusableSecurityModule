package com.darpan.security.service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MfaRequiredResponse {
    private Long userId;
    private String message;
    @Builder.Default
    private boolean mfaRequired = true;
    private String[] availableMethods;
    private String maskedEmail;
    private String maskedPhone;
}
