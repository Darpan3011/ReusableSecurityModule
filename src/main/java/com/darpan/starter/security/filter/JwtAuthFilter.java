package com.darpan.starter.security.filter;

import com.darpan.starter.security.jwt.JwtTokenProvider;
import com.darpan.starter.security.properties.SecurityProperties;
import com.darpan.starter.security.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final TokenService tokenService;
    private final SecurityProperties securityProperties;

    public JwtAuthFilter(JwtTokenProvider tokenProvider, TokenService tokenService, SecurityProperties securityProperties) {
        this.tokenProvider = tokenProvider;
        this.tokenService = tokenService;
        this.securityProperties = securityProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        
        // Check if path matches any public endpoint pattern
        boolean isPublic = securityProperties.getPublicEndpoints().stream()
                .anyMatch(endpoint -> {
                    // Handle wildcard matching simple implementation
                    if (endpoint.endsWith("/**")) {
                        String base = endpoint.substring(0, endpoint.length() - 3);
                        return path.startsWith(base);
                    }
                    return path.equals(endpoint);
                });

        // Also skip OAuth2 endpoints
        if (isPublic || 
            path.startsWith("/oauth2/") || 
            path.startsWith("/login/oauth2/") || 
            path.startsWith("/login/")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                String token = header.substring(7);
                boolean isValid = tokenProvider.validateToken(token) && tokenService.isTokenPresentInDB(token);
                if (!isValid) {
                    SecurityContextHolder.clearContext();
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Invalid or expired token\"}");
                    return; // stop further filter chain
                }

                // Token is valid — set authentication
                Authentication auth = tokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (Exception ex) {
            log.error("JWT processing failed: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(request, response);
    }
}
