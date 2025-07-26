package com.example.interact.service;

import com.example.interact.dtos.authentication.LoginResponse;
import com.example.interact.dtos.authentication.LoginUserDto;
import com.example.interact.dtos.authentication.RegisterUserDto;
import com.example.interact.dtos.authentication.UserDto;
import com.example.interact.exception.AuthenticatedUserNotFoundException;
import com.example.interact.exception.UserAlreadyExistsException;
import com.example.interact.model.UserEntity;
import com.example.interact.repository.UserRepository;
import com.example.interact.utils.ModelConverter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class AuthenticationService {

    @Value("${app.redis.keys.blacklisted-tokens}")
    private String blacklistedTokensSet;

    @Value("${app.jwt.access-token-name}")
    private String accessTokenName;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ActiveUserService activeUserService;
    private final ModelConverter modelConverter;
    private final HttpServletRequest request;
    private final RedisTemplate<String, Object> redisTemplate;
    private final HttpServletResponse response;

    public AuthenticationService(
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            UserRepository userRepository,
            ActiveUserService activeUserService,
            ModelConverter modelConverter,
            HttpServletRequest request,
            HttpServletResponse response,
            RedisTemplate<String, Object> redisTemplate
    ) {
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.activeUserService = activeUserService;
        this.modelConverter = modelConverter;
        this.request = request;
        this.response = response;
        this.redisTemplate = redisTemplate;
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

        // add user to active users in redis db
        activeUserService.addActiveUser(user.getUuid());

        // set jwt token to cookie
        Cookie cookie = new Cookie(accessTokenName, token);
        System.out.println(accessTokenName);
        response.addCookie(cookie);

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

        // add user to active users in redis db
        activeUserService.addActiveUser(user.getUuid());

        // set jwt token to cookie
        Cookie cookie = new Cookie(accessTokenName, token);
        cookie.setHttpOnly(true);
        /// cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) jwtService.getExpirationTime());
        response.addCookie(cookie);

        return new LoginResponse(token, jwtService.getExpirationTime());
    }

    public void logout() {
        /// remove user from acitve users
        UUID uuid = getAuthenticatedUser().getUuid();
        activeUserService.removeActiveUser(uuid);

        ///  delete cookie with token from cookie
        Cookie cookie = new Cookie(accessTokenName, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

    }

    public UserDto getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && !"anonymousUser".equals(authentication.getPrincipal())) {
            String username = ((UserDetails) authentication.getPrincipal()).getUsername();
            UserEntity currentUser = userRepository.findByUsername(username).orElseThrow(() -> new AuthenticatedUserNotFoundException("Current user not found in database"));
            return modelConverter.convert(currentUser, UserDto.class);
        }

        throw new AuthenticatedUserNotFoundException("No authenticated user found");
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(accessTokenName)) {
                    return cookie.getValue();
                }
            }
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }


    private void blacklistToken(String token) {
        Date expirationDate = jwtService.extractExpiration(token);
        long timeLeft = expirationDate.getTime() - System.currentTimeMillis();

        String redisKey = blacklistedTokensSet + ":" + token;
        redisTemplate.opsForValue().set(redisKey, "blacklisted", timeLeft, TimeUnit.MILLISECONDS);
    }


}
