package com.darpan.starter.security.model;

import java.util.List;
import java.util.Map;

public record CurrentUser(
        String authType,
        String username,              // for JWT/UserDetails
        Map<String, Object> attributes, // for OAuth2 (GitHub profile etc.)
        List<String> authorities
) {}
