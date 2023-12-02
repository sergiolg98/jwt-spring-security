package com.sergioferlg.security.config;

import com.sergioferlg.security.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {    //to be loaded on startup

    private final UserRepository userRepository;
    @Bean
    public UserDetailsService userDetailsService(){                                     //will hold the implementation for loadUserByUsername method of the functional interface
        return (username) -> userRepository.findByEmail(username)                       //we use the argument of lambda
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));    //handle the Optional
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        //Data Access object responsible to fetch user details and also encode password
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());

        //Password encoder
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //Authenticate user based or using just the username and password
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        //config already holds the information about the authentication manager - comes from application
        return config.getAuthenticationManager();
    }
}
