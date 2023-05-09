package com.example.backend.controller;

import com.example.backend.dto.UserRequest;
import com.example.backend.entity.User;
import com.example.backend.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.example.backend.service.UserService;

import javax.validation.Valid;
import java.util.List;
import javax.servlet.http.HttpServletRequest;


@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private HttpServletRequest request;

    @GetMapping("/fetchAll")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{userId}")
    public ResponseEntity<User> getUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUser(Long.parseLong(userId)));
    }

    @GetMapping("/current-user")
    public ResponseEntity<UserRequest> getCurrentUser() {
        try {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                String token = authorizationHeader.substring(7);
                String username = userService.getUsernameFromToken(token);
                UserRequest userRequest = userService.getUserByUsername(username);
                return ResponseEntity.ok(userRequest);
            } else {
                throw new IllegalArgumentException("Invalid Authorization header");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
