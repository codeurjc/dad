package es.codeurjc.dad.seg.ejem2;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

	/** Quién soy según el token: útil para entender qué llega a la aplicación */
	@GetMapping("/api/me")
	public Map<String, Object> me(Authentication authentication, @AuthenticationPrincipal Jwt jwt) {
		List<String> authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
		return Map.of(
				"usuario", authentication.getName(),
				"authorities", authorities,
				"emisor", String.valueOf(jwt.getIssuer()),
				"caduca", String.valueOf(jwt.getExpiresAt()));
	}
}
