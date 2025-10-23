package com.darpan.starter.security.jwt;

import com.darpan.starter.security.properties.SecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
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

    public JwtTokenProvider(SecurityProperties props) {
        System.out.println(">>> Inside JwtTokenProvider constructor <<<");
        System.out.println(">>> props.jwtSecret = " + props.getJwtSecret());
        if (props.getJwtSecret() == null || props.getJwtSecret().length() < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 characters");
        }
        this.key = Keys.hmacShaKeyFor(props.getJwtSecret().getBytes(StandardCharsets.UTF_8));
        this.validityMillis = props.getJwtExpirationSeconds() * 1000L;
        this.refreshValidityMillis = props.getRefreshTokenExpirationSeconds() * 1000L;
    }

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

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return claims.getBody().getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        String username = claims.getSubject();
        // build minimal UserDetails with username; parent app should resolve full user as needed
        UserDetails user = org.springframework.security.core.userdetails.User.withUsername(username)
                .password("[PROTECTED]").authorities("ROLE_USER").accountExpired(false).accountLocked(false).credentialsExpired(false).disabled(false)
                .build();
        return new UsernamePasswordAuthenticationToken(user, token, user.getAuthorities());
    }

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
     */
    public String getUsername(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
}
