package com.darpan.starter.security.eventlistener;

import com.darpan.starter.security.repository.OAuthSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuthLogoutHandler implements LogoutHandler {

    private final OAuthSessionRepository sessionRepo;

    @Override
    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String sessionId = request.getSession(false) != null ? request.getSession(false).getId() : null;
        if (sessionId == null) {
            log.warn("Logout called but no active session found");
            return;
        }

        sessionRepo.findBySessionId(sessionId).ifPresentOrElse(session -> {
            session.setLogoutTime(OffsetDateTime.now());
            sessionRepo.save(session);
            log.info("Updated logoutTime for session {}", sessionId);
        }, () -> log.warn("No DB session found for id {}", sessionId));
    }
}
