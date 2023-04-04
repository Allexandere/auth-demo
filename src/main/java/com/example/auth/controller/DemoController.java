package com.example.auth.controller;

import com.example.auth.model.Role;
import com.example.auth.model.dto.UserDto;
import com.example.auth.model.entity.UserEntity;
import com.example.auth.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.RolesAllowed;
import java.time.Instant;

import static java.lang.String.format;
import static java.util.stream.Collectors.joining;

@Tag(name = "Demo")
@RestController
@RequestMapping(path = "/demo")
public class DemoController {

    @GetMapping("/admin-message")
    @RolesAllowed("ADMIN")
    public String getAdminMessage() {
        return "Only admin can see this message";
    }

    @GetMapping("/user-message")
    @RolesAllowed("USER")
    public String getUserMessage() {
        return "Only user can see this message";
    }

    @GetMapping("/auth-message")
    @RolesAllowed({"ADMIN", "USER"})
    public String getAuthenticatedMessage() {
        return "Only authenticated user can see this message";
    }

    @GetMapping("/public-message")
    public String getPublicMessage() {
        return "Everyone can see this message";
    }

}
