package com.example.backend.controller;

import com.example.backend.dto.UserRequest;
import com.example.backend.entity.User;
import com.example.backend.service.AuthService;
import com.example.backend.service.AuthenticationResponse;
import com.example.backend.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<User> saveUser(@RequestBody @Valid UserRequest userRequest) {
        User savedUser = userService.saveUser(userRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> request, HttpServletResponse response) {
        try {
            String email = request.get("email");
            String password = request.get("password");
            String token = authService.login(email, password, response);
            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("token", token);
            return ResponseEntity.ok(responseBody);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}