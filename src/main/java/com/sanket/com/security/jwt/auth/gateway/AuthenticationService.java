package com.sanket.com.security.jwt.auth.gateway;

import com.sanket.com.security.jwt.config.JwtService;
import com.sanket.com.security.jwt.user.Role;
import com.sanket.com.security.jwt.user.User;
import com.sanket.com.security.jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public String register(RegisterRequest request) {
        if (repository.findByEmail(request.getEmail()).isEmpty()) {
            var user = User.builder()
                    .firstName(request.getFirstName())
                    .lastName(request.getLastName())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(Role.USER)
                    .build();
            repository.save(user);
            return user.getEmail();
        } else {
            return "Username Already Exists!!";
        }
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        if (SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            User user;
            try {
                user = repository.findByEmail(request.getEmail()).orElseThrow();
            } catch (NoSuchElementException e) {
                return AuthenticationResponse.builder().token(null).build();
            }
            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                var jwtToken = jwtService.generateToken(user);
                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .build();
            }
        }
        return AuthenticationResponse.builder().token(null).build();
    }
}
