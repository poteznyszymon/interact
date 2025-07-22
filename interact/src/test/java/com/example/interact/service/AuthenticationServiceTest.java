package com.example.interact.service;

import com.example.interact.dtos.authentication.LoginResponse;
import com.example.interact.dtos.authentication.LoginUserDto;
import com.example.interact.dtos.authentication.RegisterUserDto;
import com.example.interact.exception.UserAlreadyExistsException;
import com.example.interact.model.UserEntity;
import com.example.interact.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.mockito.Mockito.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuthenticationService authenticationService;

    @AfterEach
    void afterEach() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void registerUser_shouldReturnLoginResponse() {
        RegisterUserDto dto = new RegisterUserDto("user", "user@email.com", "pass", "John", "Doe");
        UserEntity newUser = new UserEntity();
        newUser.setUsername(dto.getUsername());
        newUser.setEmail(dto.getEmail());
        newUser.setFirstName(dto.getFirstName());
        newUser.setLastName(dto.getLastName());
        newUser.setPassword(dto.getPassword());

        when(userRepository.existsUserEntityByEmail(dto.getEmail())).thenReturn(false);
        when(userRepository.existsUserEntityByUsername(dto.getUsername())).thenReturn(false);
        when(passwordEncoder.encode(dto.getPassword())).thenReturn("encodedPassword");

        when(userRepository.save(any(UserEntity.class)))
                .thenAnswer(invocation -> {
                    UserEntity savedUser = invocation.getArgument(0);
                    savedUser.setUuid(UUID.randomUUID());
                    return savedUser;
                });

        Authentication mockAuthentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(mockAuthentication);

        when(jwtService.generateToken(any(UserEntity.class))).thenReturn("mock-token");
        when(jwtService.getExpirationTime()).thenReturn(3600L);

        LoginResponse result = authenticationService.registerUser(dto);

        assertNotNull(result);
        assertEquals("mock-token", result.getToken());
        assertEquals(3600L, result.getExpireIn());

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void registerUser_shouldThrowUserUserAlreadyExists_whenEmailExists() {
        RegisterUserDto dto = new RegisterUserDto("user", "user@email.com", "pass", "John", "Doe");
        when(userRepository.existsUserEntityByEmail(anyString())).thenReturn(true);

        assertThrows(UserAlreadyExistsException.class, () -> authenticationService.registerUser(dto));
    }

    @Test
    public void registerUser_shouldThrowUserUserAlreadyExists_whenUsernameExists() {
        RegisterUserDto dto = new RegisterUserDto("user", "user@email.com", "pass", "John", "Doe");
        when(userRepository.existsUserEntityByEmail(anyString())).thenReturn(false);
        when(userRepository.existsUserEntityByUsername(anyString())).thenReturn(true);

        assertThrows(UserAlreadyExistsException.class, () -> authenticationService.registerUser(dto));
    }

    @Test
    public void loginUser_shouldReturnLoginResponse() {
        LoginUserDto dto = new LoginUserDto("user", "pass");
        UserEntity user = new UserEntity();
        user.setUsername(dto.getUsername());
        user.setPassword(dto.getPassword());

        Authentication mockAuthentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(mockAuthentication);
        when(mockAuthentication.getPrincipal()).thenReturn(user);

        when(jwtService.generateToken(any(UserEntity.class))).thenReturn("mock-token");
        when(jwtService.getExpirationTime()).thenReturn(3600L);

        var result = authenticationService.loginUser(dto);

        assertNotNull(result);
        assertEquals("mock-token", result.getToken());
        assertEquals(3600L, result.getExpireIn());

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void loginUser_shouldThrowBadCredentialsException_whenInvalidCredentials() {
        LoginUserDto dto = new LoginUserDto("user", "pass");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenThrow(new BadCredentialsException("Invalid credentials"));
        assertThrows(BadCredentialsException.class, () -> authenticationService.loginUser(dto));

        verifyNoInteractions(jwtService);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}