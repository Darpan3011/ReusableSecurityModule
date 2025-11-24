package com.darpan.starter.security.service.dto;

import com.darpan.starter.security.service.enums.AuthEnum;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
public class AuthType {

    private AuthEnum type;
}
