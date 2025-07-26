package com.example.interact.dtos.authentication;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginUserDto {

    @NotBlank
    private String username;
    @NotBlank
    private String password;

}
