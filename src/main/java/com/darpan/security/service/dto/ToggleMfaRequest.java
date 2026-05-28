package com.darpan.security.service.dto;

import lombok.Data;

@Data
public class ToggleMfaRequest {
    private boolean enabled;
}
