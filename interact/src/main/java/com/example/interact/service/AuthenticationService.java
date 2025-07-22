package com.example.interact.service;

import com.example.interact.dtos.authentication.LoginResponse;
import com.example.interact.dtos.authentication.LoginUserDto;
import com.example.interact.dtos.authentication.RegisterUserDto;
import com.example.interact.exception.AuthenticatedUserNotFoundException;
import com.example.interact.exception.UserAlreadyExistsException;
import com.example.interact.model.UserEntity;
import com.example.interact.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    public AuthenticationService(
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            UserRepository userRepository
    ) {
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    public LoginResponse registerUser(RegisterUserDto registerUserDto) {

        if (userRepository.existsUserEntityByEmail(registerUserDto.getEmail())) {
            throw new UserAlreadyExistsException("Email already taken");
        }

        if (userRepository.existsUserEntityByUsername(registerUserDto.getUsername())) {
            throw new UserAlreadyExistsException("Username already taken");
        }

        UserEntity user = new UserEntity();
        user.setUsername(registerUserDto.getUsername());
        user.setEmail(registerUserDto.getEmail());
        user.setFirstName(registerUserDto.getFirstName());
        user.setLastName(registerUserDto.getLastName());
        user.setPassword(passwordEncoder.encode(registerUserDto.getPassword()));

        userRepository.save(user);

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                registerUserDto.getPassword()
        ));

        // save current user to the context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtService.generateToken(user);

        return new LoginResponse(token, jwtService.getExpirationTime());

    }

    public LoginResponse loginUser(LoginUserDto loginUserDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginUserDto.getUsername(),
                loginUserDto.getPassword()
        ));

        // save current user to the context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserEntity user = (UserEntity) authentication.getPrincipal();
        String token = jwtService.generateToken(user);

        return new LoginResponse(token, jwtService.getExpirationTime());
    }

    public UserEntity getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && !"anonymousUser".equals(authentication.getPrincipal())) {
            String username = ((UserDetails) authentication.getPrincipal()).getUsername();
            return userRepository.findByUsername(username).orElseThrow(() -> new AuthenticatedUserNotFoundException("Current user not found in database"));
        }

        throw new AuthenticatedUserNotFoundException("No authenticated user found");
    }

}
