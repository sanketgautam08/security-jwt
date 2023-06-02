package com.sanket.com.security.jwt.auth.gateway;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        String response = authenticationService.register(request);
        if("Username Already Exists!!".equals(response)){
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }else{
            return ResponseEntity.status(HttpStatus.OK).body("User Created:\n" + response);
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        try {
            AuthenticationResponse authenticationResponse = authenticationService.authenticate(request);
            if (authenticationResponse.token == null) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid Creds!!");
            } else {
                return ResponseEntity.ok(authenticationService.authenticate(request));
            }
        } catch (ExpiredJwtException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid token/Credentials");
        }

    }
}
