package com.training.springbootspringsecurityjwt;

import com.training.springbootspringsecurityjwt.domain.AppUser;
import com.training.springbootspringsecurityjwt.domain.Role;
import com.training.springbootspringsecurityjwt.services.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
public class SpringbootSpringsecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringbootSpringsecurityJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner commandLineRunner(AppUserService appUserService){
		return args -> {
			appUserService.saveRole(new Role("ROLE_USER"));
			appUserService.saveRole(new Role("ROLE_MANAGER"));
			appUserService.saveRole(new Role("ROLE_ADMIN"));
			appUserService.saveRole(new Role("ROLE_SUPER_ADMIN"));

			appUserService.saveUser(new AppUser("Nico Ardizzoli", "nardizzoli", "123456", List.of()));
			appUserService.saveUser(new AppUser("Roberto Gomez", "rgomez", "123456", List.of()));

			appUserService.addRoleToUser("nardizzoli", "ROLE_SUPER_ADMIN");
			appUserService.addRoleToUser("rgomez", "ROLE_USER");
		};
	}
}
