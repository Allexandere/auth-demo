package com.example.auth;

import com.example.auth.model.Role;
import com.example.auth.model.dto.UserDto;
import com.example.auth.model.entity.UserEntity;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;

@Component
@RequiredArgsConstructor
public class DbInitializer implements ApplicationListener<ApplicationReadyEvent> {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        userRepository.save(new UserEntity("test", passwordEncoder.encode("test")));

        UserEntity admin = new UserEntity("admin", passwordEncoder.encode("admin"));
        admin.setRole(Role.ADMIN);

        userRepository.save(admin);
    }
}
