package com.training.springbootspringsecurityjwt.services;

import com.training.springbootspringsecurityjwt.domain.AppUser;
import com.training.springbootspringsecurityjwt.domain.Role;
import com.training.springbootspringsecurityjwt.repository.AppUserRepository;
import com.training.springbootspringsecurityjwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImpl implements AppUserService, UserDetailsService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<AppUser> appUserByUsername = appUserRepository.findAppUserByUsername(username);

        if (appUserByUsername.isPresent()) {
            AppUser u = appUserByUsername.get();
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            u.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName())));
            return new User(u.getUsername(), u.getPassword(), authorities);
        } else {
            log.error("user not found"+ username);
            throw new UsernameNotFoundException("user not found" + username);
        }


    }

    @Override
    public AppUser saveUser(AppUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        log.info("saving new user {} to the database", user.getUsername());
        return appUserRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role {} to the database", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("adding role {} to user {}", roleName, username);
        AppUser appUserByUsername = appUserRepository.findAppUserByUsername(username).orElseThrow();
        Role roleByName = roleRepository.findRoleByName(roleName);
        //aca no hay que volver a llamar al metodo save, porque le pusimos la anotation @Transactional al servicio, asi que lo hace solo
        appUserByUsername.getRoles().add(roleByName);


    }

    @Override
    public AppUser getAppUser(String username) {
        log.info("fetching user {} from the database", username);
        return appUserRepository.findAppUserByUsername(username).orElseThrow(() -> {
            throw new IllegalStateException("User not found");
        });
    }

    @Override
    public List<AppUser> getAppUsers() {
        log.info("fetching all users");
        return appUserRepository.findAll();
    }
}
