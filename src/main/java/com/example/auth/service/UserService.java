package com.example.auth.service;

import com.example.auth.model.dto.UserDto;
import com.example.auth.model.pojo.User;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.UUID;

public interface UserService extends UserDetailsService {
    User createUser(UserDto userDto);
    User getUser(UUID id);
    User deleteUser(UUID id);
}
