package com.titusw.security;

import com.titusw.security.auth.AuthenticationService;
import com.titusw.security.auth.RegisterRequest;
import com.titusw.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.titusw.security.user.Role.ADMIN;
import static com.titusw.security.user.Role.MANAGER;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService authenticationService
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(ADMIN)
					.build();
			System.out.println("Admin token: " + authenticationService.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("manager@mail.com")
					.password("password")
					.role(MANAGER)
					.build();
			System.out.println("Manager token: " + authenticationService.register(manager).getAccessToken());
		};
	}
}
