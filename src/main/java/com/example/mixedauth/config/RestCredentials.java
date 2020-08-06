package com.example.mixedauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.BadCredentialsException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class RestCredentials {

    private String username;
    private String password;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    static RestCredentials from(HttpServletRequest request) {
        try {
            return OBJECT_MAPPER.readValue(request.getInputStream(), RestCredentials.class);
        } catch (IOException e) {
            throw new BadCredentialsException("Could not extract credentials from request.");
        }
    }
}
