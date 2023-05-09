package com.example.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public HttpFirewall defaultHttpFirewall() {
        return new DefaultHttpFirewall();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.httpFirewall(defaultHttpFirewall());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth/login").permitAll()
                .antMatchers("/auth/signup").permitAll()
                .antMatchers("/users/**").hasAuthority("ROLE_USER")
                .antMatchers("/pet/**").hasAuthority("ROLE_USER")
                //.anyRequest().authenticated()
                .and();
                //.headers().frameOptions().disable(); // add this line if you use H2 database
    }
}