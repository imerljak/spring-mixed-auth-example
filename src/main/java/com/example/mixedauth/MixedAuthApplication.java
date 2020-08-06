package com.example.mixedauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity
@SpringBootApplication
public class MixedAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(MixedAuthApplication.class, args);
    }

}
