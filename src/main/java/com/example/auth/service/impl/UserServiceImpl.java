package com.example.auth.service.impl;

import com.example.auth.model.Role;
import com.example.auth.model.dto.UserDto;
import com.example.auth.model.entity.UserEntity;
import com.example.auth.model.pojo.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

import static java.lang.String.format;

@Service
@RequiredArgsConstructor
public class UserServiceImpl extends ModelMapper implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User createUser(UserDto userDto) {
        UserEntity userEntity = new UserEntity(userDto.getUsername(), passwordEncoder.encode(userDto.getPassword()));
        return this.map(userRepository.save(userEntity), User.class);
    }

    @Override
    public User getUser(UUID id) {
        return this.map(userRepository.findById(id), User.class);
    }

    @Override
    public User deleteUser(UUID id) {
        UserEntity userEntity = userRepository.findById(id).get();
        userRepository.deleteById(id);
        return this.map(userEntity, User.class);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(format("User: %s, not found", username)));
    }
}
