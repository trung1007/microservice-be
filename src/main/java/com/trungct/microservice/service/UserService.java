package com.trungct.microservice.service;

import com.trungct.microservice.domain.UserEntity;

import java.util.List;


public interface UserService {

    public UserEntity handleCreateUser(UserEntity userEntity);

    public List<UserEntity> getAllUsers();

    public UserEntity getUserByUserName(String username);
}
