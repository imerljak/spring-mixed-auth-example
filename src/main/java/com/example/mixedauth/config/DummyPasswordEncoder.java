package com.example.mixedauth.config;

import org.springframework.security.crypto.password.PasswordEncoder;

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
