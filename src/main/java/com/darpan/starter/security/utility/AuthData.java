package com.darpan.starter.security.utility;

import com.darpan.starter.security.model.CurrentUser;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuthData {

    public static CurrentUser resolveCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        List<String> authorities = authentication.getAuthorities().stream()
                .map(Object::toString).toList();

        Object principal = authentication.getPrincipal();

        if (principal instanceof org.springframework.security.oauth2.core.user.OAuth2User oAuth2User) {
            // OAuth2 session flow
            String name = oAuth2User.getName(); // provider user id (e.g., GitHub id)
            return new CurrentUser("OAUTH2", name, oAuth2User.getAttributes(), authorities, false);
        } else if (principal instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
            // JWT (or form login with UserDetails)
            boolean mfaEnabled = false;
            Map<String, Object> attributes = new HashMap<>();
            if (userDetails instanceof com.darpan.starter.security.model.User user) {
                mfaEnabled = user.isMfaEnabled();
                attributes.put("email", user.getEmail());
            }
            return new CurrentUser("USER_DETAILS", userDetails.getUsername(), attributes, authorities, mfaEnabled);
        } else if (principal instanceof java.security.Principal p) {
            return new CurrentUser("PRINCIPAL", p.getName(), Collections.emptyMap(), authorities, false);
        } else {
            return new CurrentUser(principal.getClass().getSimpleName(), String.valueOf(principal), Collections.emptyMap(), authorities, false);
        }
    }
}
