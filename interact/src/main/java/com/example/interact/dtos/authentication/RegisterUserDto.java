package com.example.interact.dtos.authentication;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterUserDto {

    @NotBlank(message = "Username cannot be empty")
    @Size(max = 20)
    private String username;
    @NotBlank(message = "FirstName cannot be empty")
    private String firstName;
    @NotBlank(message = "LastName cannot be empty")
    private String lastName;
    @NotBlank(message = "Email cannot be empty")
    @Email(message = "Incorrect email format")
    @Size(max = 100)
    private String email;
    @NotBlank(message = "Password cannot be empty")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String password;
}
