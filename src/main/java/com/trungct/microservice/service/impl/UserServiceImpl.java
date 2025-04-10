package com.trungct.microservice.service.impl;

import com.trungct.microservice.domain.UserEntity;
import com.trungct.microservice.repository.UserRepository;
import com.trungct.microservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserEntity handleCreateUser(UserEntity userEntity) {
        return this.userRepository.save(userEntity);
    }

    @Override
    public List<UserEntity> getAllUsers() {
        return this.userRepository.findAll();
    }

    @Override
    public UserEntity getUserByUserName(String username) {
        return this.userRepository.findByUsername(username);
    }


}
