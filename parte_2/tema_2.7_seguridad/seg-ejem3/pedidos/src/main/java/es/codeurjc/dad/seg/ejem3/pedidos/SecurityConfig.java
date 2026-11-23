package es.codeurjc.dad.seg.ejem3.pedidos;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	/**
	 * Para centrarnos en la llamada saliente, la API de pedidos es abierta.
	 * En un sistema real también sería un resource server (como seg-ejem2).
	 * Sin esta configuración, Spring Boot activaría el login con OAuth2 en todas las URLs.
	 */
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
			.csrf(csrf -> csrf.disable());
		return http.build();
	}
}
