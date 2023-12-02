package com.sergioferlg.security.services;

import com.sergioferlg.security.models.dtos.requests.AuthenticationRequest;
import com.sergioferlg.security.models.dtos.requests.RegisterRequest;
import com.sergioferlg.security.models.dtos.responses.AuthenticationResponse;
import com.sergioferlg.security.models.entities.User;
import com.sergioferlg.security.models.types.Role;
import com.sergioferlg.security.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request){

        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        //Using AuthenticationManger Bean - has a method called authenticate to allow to authenticate user based on username and password
        //Authenticate user
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(    //special class
                request.getEmail(),
                request.getPassword())
        );

        //Above will manage everything for authentication, will throw an exception if something goes wrong
        //Now if everything goes fine, token must be created and sent back to user

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();                             //needed because of Optional
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }




}
