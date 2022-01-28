package com.training.springbootspringsecurityjwt.services;

import com.training.springbootspringsecurityjwt.domain.AppUser;
import com.training.springbootspringsecurityjwt.domain.Role;

import java.util.List;

public interface AppUserService {

    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getAppUser(String username);
    List<AppUser> getAppUsers();
}
