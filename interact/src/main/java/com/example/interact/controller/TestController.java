package com.example.interact.controller;

import com.example.interact.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api")
@RestController
public class TestController {

    @Autowired
    AuthenticationService authenticationService;

    @GetMapping("test")
    public String test() {
        return "chuj";
    }
}
