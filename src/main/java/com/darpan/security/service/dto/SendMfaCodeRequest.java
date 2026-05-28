package com.darpan.security.service.dto;

import com.darpan.security.service.enums.MfaDeliveryMethod;
import lombok.Data;

@Data
public class SendMfaCodeRequest {
    private Long userId;
    private MfaDeliveryMethod method;
}
