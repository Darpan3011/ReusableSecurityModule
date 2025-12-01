package com.darpan.starter.security.service.dto;

import com.darpan.starter.security.service.enums.MfaDeliveryMethod;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SetMfaDeliveryMethodRequest {
    private MfaDeliveryMethod deliveryMethod;
}
