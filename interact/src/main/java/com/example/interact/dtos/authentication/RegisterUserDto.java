package com.example.interact.dtos.authentication;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RegisterUserDto {
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
