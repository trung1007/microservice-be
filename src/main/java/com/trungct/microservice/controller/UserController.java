package com.trungct.microservice.controller;

import com.trungct.microservice.domain.UserEntity;
import com.trungct.microservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @GetMapping("")
    public ResponseEntity<List<UserEntity>> getAllUsers() {
        List<UserEntity> userEntities = userService.getAllUsers();
        return ResponseEntity.ok(userEntities);
    }

    @PostMapping("/create")
    public ResponseEntity<UserEntity> createUser(@RequestBody UserEntity userEntity) {
        String hashPassword = passwordEncoder.encode(userEntity.getPassword());
        userEntity.setPassword(hashPassword);
        UserEntity createdUserEntity = this.userService.handleCreateUser(userEntity);
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Custom-Header", "CreatedSuccessfully");

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .headers(headers)
                .body(createdUserEntity);
    }
}
