package com.sergioferlg.security.config;

import com.sergioferlg.security.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtService jwtService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain             //chain of responsability design pattern
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization"); //where we get the Bearer Token
        final String jwtToken;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request, response);                    //pass the req and res to the next filter
            return;                                                     //stop execution
        }

        jwtToken = authHeader.substring(7);                   //after "Bearer "
        userEmail =  jwtService.extractUserEmail(jwtToken);             //TODO extract userEmail from JWT token


    }
}
