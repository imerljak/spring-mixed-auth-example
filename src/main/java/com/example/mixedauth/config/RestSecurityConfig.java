package com.example.mixedauth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@Order(1)
@Configuration
public class RestSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JWTProvider jwtProvider;

    public RestSecurityConfig(JWTProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(new DummyPasswordEncoder())
                .withUser(User.withUsername("rest_admin")
                        .password("321")
                        .roles("ADMIN"));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /* matches only routes starting with /rest */
        http.antMatcher("/rest/**")
                .cors().and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/rest/auth").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().exceptionHandling().authenticationEntryPoint(restfulAuthenticationEntryPoint())
                .and()
                .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(authorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .formLogin().disable();
    }

    private AuthenticationEntryPoint restfulAuthenticationEntryPoint() {
        return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private RestAuthorizationFilter authorizationFilter() {
        return new RestAuthorizationFilter("/rest/**", userDetailsService(), jwtProvider);
    }

    private RestAuthenticationFilter authenticationFilter() throws Exception {
        return new RestAuthenticationFilter("/rest/auth", authenticationManager(), jwtProvider);
    }
}
