package com.darpan.security.service.dto;

import lombok.Data;

@Data
public class VerifyCodeRequest {
    private Long userId;
    private String code;
}
