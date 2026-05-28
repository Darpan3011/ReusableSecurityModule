package com.darpan.security.jwt;

import com.darpan.security.model.User;
import com.darpan.security.properties.SecurityProperties;
import com.darpan.security.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final Key key;
    private final long validityMillis;
    private final long refreshValidityMillis;
    private final UserRepository userRepository;

    public JwtTokenProvider(SecurityProperties props, UserRepository userRepository) {
        if (props.getJwtSecret() == null || props.getJwtSecret().length() < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 characters");
        }
        this.key = Keys.hmacShaKeyFor(props.getJwtSecret().getBytes(StandardCharsets.UTF_8));
        this.validityMillis = props.getJwtExpirationSeconds() * 1000L;
        this.refreshValidityMillis = props.getRefreshTokenExpirationSeconds() * 1000L;
        this.userRepository = userRepository;
    }

    /**
     * Generate an access token for a user
     * @param username Username
     * @param userId User ID
     * @return Signed JWT access token
     */
    public String generateAccessToken(String username, Long userId) {
        Instant now = Instant.now();
        Instant exp = now.plusMillis(validityMillis);
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .claim("uid", userId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(key)
                .compact();
    }

    /**
     * Generate a refresh token for a user
     * @param username Username
     * @param userId User ID
     * @return Signed JWT refresh token
     */
    public String generateRefreshToken(String username, Long userId) {
        Instant now = Instant.now();
        Instant exp = now.plusMillis(refreshValidityMillis);
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .claim("uid", userId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(key)
                .compact();
    }

    /**
     * Validate a JWT token
     * @param token JWT token string
     * @return true if token is valid and not expired
     */
    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return claims.getBody().getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Get Authentication object from a token
     * @param token JWT token string
     * @return Authentication object
     */
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        String username = claims.getSubject();
        // build minimal UserDetails with username; parent app should resolve full user as needed
        User user = userRepository.findByUsername(username).get();
        return new UsernamePasswordAuthenticationToken(user, token, user.getAuthorities());
    }

    /**
     * Get JTI (JWT ID) from a token
     * @param token JWT token string
     * @return JTI string or null if invalid
     */
    public String getJti(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getId();
        } catch (Exception e) {
            return null;
        }
    }

    public long getAccessExpiryMillis() { return validityMillis; }
    public long getRefreshExpiryMillis() { return refreshValidityMillis; }

    /**
     * Extracts the subject (username) from a signed JWT using the configured signing key.
     * @param token JWT token string
     * @return Username
     */
    public String getUsername(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
}
