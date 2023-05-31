package com.sanket.com.security.jwt.auth.gateway;

import com.sanket.com.security.jwt.config.JwtService;
import com.sanket.com.security.jwt.config.manager.CustomAuthenticationManager;
import com.sanket.com.security.jwt.user.Role;
import com.sanket.com.security.jwt.user.User;
import com.sanket.com.security.jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthenticationResponse register(RegisterRequest request) {
        if(repository.findByEmail(request.getEmail()).isEmpty()){
            var user = User.builder()
                    .firstName(request.getFirstName())
                    .lastName(request.getLastName())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(Role.USER)
                    .build();
            repository.save(user);
            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        }
        else{
            return new AuthenticationResponse(null);
        }
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        if(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()){
            var user = repository.findByEmail(request.getEmail()).orElseThrow();
            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        }
        return AuthenticationResponse.builder().token(null).build();
    }
}
