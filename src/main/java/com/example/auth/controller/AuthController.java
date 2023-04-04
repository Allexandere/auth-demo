package com.example.auth.controller;

import com.example.auth.model.Role;
import com.example.auth.model.dto.UserDto;
import com.example.auth.model.entity.UserEntity;
import com.example.auth.model.pojo.User;
import com.example.auth.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
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
import java.util.Map;

import static java.lang.String.format;
import static java.util.stream.Collectors.joining;

@Tag(name = "Auth")
@RestController
@RequestMapping(path = "/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final UserService userService;

    @PostMapping
    public ResponseEntity<String> login(@RequestBody UserDto userDto) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userDto.getUsername(), userDto.getPassword())
        );
        UserEntity principal = (UserEntity) authentication.getPrincipal();

        Instant now = Instant.now();
        long expiry = 36000L;

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("example.io")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(format("%s,%s", principal.getId(), principal.getUsername()))
                .claim("roles", scope)
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, token)
                .body(token);
    }

    @GetMapping("/message")
    @RolesAllowed("ADMIN")
    public String getPrivateInfo() {
        return "Only admin can see this";
    }
}
