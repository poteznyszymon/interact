package com.example.interact.controller;

import com.example.interact.dtos.authentication.LoginResponse;
import com.example.interact.dtos.authentication.LoginUserDto;
import com.example.interact.dtos.authentication.RegisterUserDto;
import com.example.interact.service.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> registerUser(@Valid @RequestBody RegisterUserDto registerUserDto) {
      return ResponseEntity.ok(authenticationService.registerUser(registerUserDto));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> loginUser(@RequestBody LoginUserDto loginUserDto) {
        return ResponseEntity.ok(authenticationService.loginUser(loginUserDto));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser() {
        System.out.println("dziala");
        authenticationService.logout();
        return ResponseEntity.ok("Successfully logged out");
    }

}
