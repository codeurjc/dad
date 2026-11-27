package es.codeurjc.dad.seg.ejem2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class KeycloakRolesConverterTest {

	private final KeycloakRolesConverter converter = new KeycloakRolesConverter();

	@Test
	void convierteLosRolesDelRealm() {
		Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256")
				.claim("realm_access", Map.of("roles", List.of("user", "admin"))).build();
		List<String> authorities = converter.convert(jwt).stream().map(GrantedAuthority::getAuthority).toList();
		assertEquals(List.of("ROLE_user", "ROLE_admin"), authorities);
	}

	@Test
	void sinRolesNoHayAuthorities() {
		Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "x").build();
		assertTrue(converter.convert(jwt).isEmpty());
	}
}
