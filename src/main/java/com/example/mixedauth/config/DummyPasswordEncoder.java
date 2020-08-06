package com.example.mixedauth.config;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Dummy password encoder - DO NOT USE IN PRODUCTION
 *
 * Does not encode anything, only serves a bypass to use simple plain text passwords in this example
 */
public class DummyPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence charSequence) {
        return charSequence.toString();
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return s.compareTo(charSequence.toString()) == 0;
    }
}
