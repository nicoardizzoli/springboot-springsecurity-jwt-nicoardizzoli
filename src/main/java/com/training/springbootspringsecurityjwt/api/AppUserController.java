package com.training.springbootspringsecurityjwt.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.training.springbootspringsecurityjwt.domain.AppUser;
import com.training.springbootspringsecurityjwt.domain.Role;
import com.training.springbootspringsecurityjwt.dtos.RoleToUserDTO;
import com.training.springbootspringsecurityjwt.services.AppUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/api")
public class AppUserController {
    private final AppUserService appUserService;

    @GetMapping(path = "/users")
    public ResponseEntity<List<AppUser>> getAppUsers() {
        return ResponseEntity.ok().body(appUserService.getAppUsers());
    }


    @PostMapping(path = "/user/save")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {
        URI uri = URI.create(String.valueOf(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save")));
        return ResponseEntity.created(uri).body(appUserService.saveUser(user));
    }

    @PostMapping(path = "/role/save")
    public ResponseEntity<Role> saveUser(@RequestBody Role role) {
        URI uri = URI.create(String.valueOf(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save")));
        return ResponseEntity.created(uri).body(appUserService.saveRole(role));
    }

    @PostMapping(path = "/role/addroletouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserDTO roleToUserDTO) {
        appUserService.addRoleToUser(roleToUserDTO.getUsername(), roleToUserDTO.getRoleName());
        return ResponseEntity.ok().build();
    }
    @GetMapping(path = "/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        //esto lo pone el header, el "Bearer "
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                //le sacamos la palabra bearer, y obtenemos el token
                String token = authorizationHeader.substring("Bearer ".length());

                //lo decodificamos
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(token);
                //aca ya tenemos el token decodificado, lo que es CLAIM es lo que le fimos agregando al token
                String username = decodedJWT.getSubject();
                AppUser appUser = appUserService.getAppUser(username);

//                creo el token de nuevo

                String access_token = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);

                String refresh_token = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 20 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .sign(algorithm);


                //para devolver los tokens en el header del response
//        response.setHeader("access_token", access_token);
//        response.setHeader("refresh_token", refresh_token);

                //Para devolver los tokens en el body del response.
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token",access_token);
                tokens.put("refresh_token",refresh_token);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            }catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
}
