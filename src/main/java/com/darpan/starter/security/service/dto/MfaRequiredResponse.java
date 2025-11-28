package com.darpan.starter.security.service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MfaRequiredResponse {
    private Long userId;
    private String message;
    private boolean mfaRequired = true;
}
