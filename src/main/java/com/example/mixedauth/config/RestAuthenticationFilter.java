package com.example.mixedauth.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Filters and tries to authenticate REST based requests and returns a JWT token.
 * Expects a POST request with a json request body matching {@link RestCredentials}
 */
public class RestAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final JWTProvider jwtProvider;

    protected RestAuthenticationFilter(RequestMatcher matcher, AuthenticationManager authenticationManager, JWTProvider jwtProvider) {
        super(matcher);
        this.jwtProvider = jwtProvider;
        setAuthenticationManager(authenticationManager);
    }

    protected RestAuthenticationFilter(String path, AuthenticationManager authenticationManager, JWTProvider jwtProvider) {
        this(new AntPathRequestMatcher(path), authenticationManager, jwtProvider);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        /*
         * Only accepts POST requests in this filter.
         */
        if (!request.getMethod().equalsIgnoreCase("POST")) {
            throw new MethodNotAllowedAuthenticationException(request.getMethod());
        }

        final RestCredentials credentials = RestCredentials.from(request);

        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(
                credentials.getUsername(),
                credentials.getPassword()
        ));
    }

    /**
     * On unsuccessful authentication set response status for proper handling.
     * If not overridden this method would redirect to /login
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        if (failed instanceof MethodNotAllowedAuthenticationException) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * On successful authentication build and return a JWT token for use.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        jwtProvider.writeToResponse(response, authResult);
    }

    /**
     * Custom exception to handle failed authentication when request method is invalid.
     */
    static class MethodNotAllowedAuthenticationException extends AuthenticationException {
        public MethodNotAllowedAuthenticationException(String msg) {
            super(msg);
        }
    }
}
