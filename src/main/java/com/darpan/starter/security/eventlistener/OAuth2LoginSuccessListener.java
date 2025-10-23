package com.darpan.starter.security.eventlistener;

import com.darpan.starter.security.model.OAuthSession;
import com.darpan.starter.security.model.OAuthUser;
import com.darpan.starter.security.repository.OAuthSessionRepository;
import com.darpan.starter.security.repository.OAuthUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Slf4j
@Component
public class OAuth2LoginSuccessListener {

    private final OAuthUserRepository userRepo;
    private final OAuthSessionRepository sessionRepo;

    public OAuth2LoginSuccessListener(OAuthUserRepository userRepo, OAuthSessionRepository sessionRepo) {
        this.userRepo = userRepo;
        this.sessionRepo = sessionRepo;
    }

    public void onOAuthLoginSuccess(HttpServletRequest request, Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            log.warn("Skipping non-OAuth2 login event");
            return;
        }

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();
        String provider = oauthToken.getAuthorizedClientRegistrationId();

        String providerUserId = extractProviderUserId(provider, oAuth2User);
        if (providerUserId == null) {
            log.warn("Missing providerUserId for provider {}", provider);
            return;
        }

        OAuthUser user = userRepo.findByProviderAndProviderUserId(provider, providerUserId).orElse(null);
        if (user == null) {
            log.warn("User not found for provider={} and id={}", provider, providerUserId);
            return;
        }

        String sessionId = request.getSession(true).getId();
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        OAuthSession session = new OAuthSession();
        session.setUser(user);
        session.setSessionId(sessionId);
        session.setLoginTime(Instant.now());
        session.setIpAddress(ip);
        session.setUserAgent(userAgent);

        sessionRepo.save(session);

        user.setLastAccess(Instant.now());
        userRepo.save(user);

        log.info("OAuth login success for [{}] ({}), sessionId={}", user.getUsername(), provider, sessionId);
    }

    private String extractProviderUserId(String provider, OAuth2User user) {
        if ("github".equalsIgnoreCase(provider)) {
            return String.valueOf(user.getAttributes().get("id"));
        } else if ("google".equalsIgnoreCase(provider)) {
            return String.valueOf(user.getAttributes().get("sub"));
        } else {
            Object sub = user.getAttributes().get("sub");
            Object id = user.getAttributes().get("id");
            return sub != null ? sub.toString() : (id != null ? id.toString() : null);
        }
    }
}
