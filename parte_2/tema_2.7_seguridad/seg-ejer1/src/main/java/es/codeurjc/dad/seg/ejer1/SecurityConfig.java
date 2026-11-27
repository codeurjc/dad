package es.codeurjc.dad.seg.ejer1;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/api/pedidos/**").hasRole("user")
				.anyRequest().denyAll())
			// Resource server: cada petición trae un JWT en "Authorization: Bearer ..."
			.oauth2ResourceServer(oauth2 -> oauth2
				.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
			// Sin sesión: el estado de autenticación viaja en el token (escalable horizontalmente)
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			// Sin cookies de sesión no hay CSRF posible
			.csrf(csrf -> csrf.disable());
		return http.build();
	}

	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setJwtGrantedAuthoritiesConverter(new KeycloakRolesConverter());
		// El nombre del usuario (authentication.getName()) es el claim preferred_username, no el "sub" (un UUID)
		converter.setPrincipalClaimName("preferred_username");
		return converter;
	}
}
