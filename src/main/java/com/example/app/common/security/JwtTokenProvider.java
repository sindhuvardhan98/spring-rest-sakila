package com.example.app.common.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private SecretKey key;

    @Value("${app.jwt.signing-key}")
    private String signingKey;

    @Value("${app.jwt.token-expiration-hours:1}")
    private int tokenExpirationHours;

    @PostConstruct
    public void init() {
        if (signingKey == null || signingKey.isBlank()) {
            throw new IllegalStateException("Signing key cannot be null or empty");
        }
        key = Keys.hmacShaKeyFor(signingKey.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(UserDetails user) {
        final var claims = Jwts.claims();
        claims.put("email", user.getUsername());
        claims.put("authorities", List.of("ROLE_READ", "ROLE_MANAGE")); // Include ROLE_READ
        claims.setIssuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()));
        claims.setExpiration(Date.from(LocalDateTime.now()
                .plusHours(tokenExpirationHours)
                .atZone(ZoneId.systemDefault()).toInstant()));
        return Jwts.builder()
                .setClaims(claims)
                .signWith(key)
                .compact();
    }

    public Claims decodeToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid or expired token", e);
        }
    }

    public boolean validateToken(String token, String email) {
        Claims claims = decodeToken(token);
        return claims.get("email").equals(email) && claims.getExpiration().after(new Date());
    }
}
