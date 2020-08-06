package com.example.mixedauth.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Authorization filter for REST requests
 */
public class RestAuthorizationFilter extends OncePerRequestFilter {

    private final AntPathRequestMatcher pathMatcher;
    private final UserDetailsService userDetailsService;
    private final JWTProvider jwtProvider;

    public RestAuthorizationFilter(String path, UserDetailsService userDetailsService, JWTProvider jwtProvider) {
        pathMatcher = new AntPathRequestMatcher(path);
        this.userDetailsService = userDetailsService;
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (!pathMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        final String bearerToken = request.getHeader("Authorization");
        if (bearerToken == null || bearerToken.trim().isEmpty()) {
            /* Uses setStatus to avoid redirection to /login */
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        try {
            final String subject = jwtProvider.parseTokenForSubject(bearerToken.replace("Bearer ", ""));

            authenticate(subject);
            chain.doFilter(request, response);
            clearAuthentication();

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Authenticates user in Spring security context.
     * @param subject user subject/username
     */
    private void authenticate(String subject) {
        final UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(),
                userDetails.getPassword(),
                userDetails.getAuthorities()
        ));
    }

    /**
     * Clears security context
     */
    private void clearAuthentication() {
        SecurityContextHolder.getContext().setAuthentication(null);
    }
}
