package com.example.interact.dtos.authentication;

import lombok.Data;

@Data
public class RegisterUserDto {
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
