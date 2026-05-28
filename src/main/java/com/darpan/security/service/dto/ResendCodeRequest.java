package com.darpan.security.service.dto;

import com.darpan.security.service.enums.MfaCodeType;
import lombok.Data;

@Data
public class ResendCodeRequest {
    private Long userId;
    private MfaCodeType type;
}
