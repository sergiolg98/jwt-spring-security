package com.sergioferlg.security.config;

import com.sergioferlg.security.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {    //to be loaded on startup

    private final UserRepository userRepository;
    @Bean
    public UserDetailsService userDetailsService(){                                     //will hold the implementation for loadUserByUsername method of the functional interface
        return (username) -> userRepository.findByEmail(username)                       //we use the argument of lambda
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));    //handle the Optional
    }

}
