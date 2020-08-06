package com.example.mixedauth.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * Helper for JWT related things.
 */
@Component
public class JWTProvider {

    public static final int FIVE_MINUTES = 5 * (60 * 1000);

    @Value("${jwt.secret.key}")
    private String secretKey;

    /**
     * Writes a JWT token to response body
     * @param response current request's response
     * @param authentication authentication for provided user/password
     */
    public void writeToResponse(HttpServletResponse response, Authentication authentication) {
        if (authentication == null) {
            return;
        }

        response.setContentType("text/plain");

        String token = generateToken(authentication);

        try {
            response.getWriter().write(token);
        } catch (IOException e) {
            throw new AuthenticationServiceException(e.getMessage(), e);
        }
    }

    /**
     * Parses request token and returns subject.
     * @param token request token extracted from Authentication header
     * @return token subject
     */
    public String parseTokenForSubject(String token) {
        return Jwts.parser()
                .setSigningKey(signingKey())
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    private String generateToken(Authentication authentication) {
        final User token = (User) authentication.getPrincipal();

        final long currentTimeMillis = System.currentTimeMillis();

        final Date issuedAt = new Date(currentTimeMillis);
        final Date expiration = new Date(currentTimeMillis + FIVE_MINUTES);

        return Jwts.builder()
                .setIssuedAt(issuedAt)
                .setSubject(token.getUsername())
                .setExpiration(expiration)
                .signWith(signingKey())
                .compact();
    }

    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

}
