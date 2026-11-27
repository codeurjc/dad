package es.codeurjc.dad.seg.ejem2;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;

/**
 * No hace falta Keycloak: jwt() mete en la petición un token ya "validado".
 * Los roles se calculan con el MISMO conversor que usa la aplicación.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ProductoControllerTest {

	private static final String NUEVO = "{\"nombre\":\"Monitor\",\"precio\":199.0}";

	@Autowired
	private MockMvc mvc;

	private static JwtRequestPostProcessor usuario(String nombre, String... roles) {
		return jwt()
				.jwt(token -> token.subject(nombre)
						.claim("preferred_username", nombre)
						.claim("realm_access", Map.of("roles", List.of(roles))))
				.authorities(new KeycloakRolesConverter());
	}

	@Test
	void listarEsPublico() throws Exception {
		mvc.perform(get("/api/productos")).andExpect(status().isOk());
	}

	@Test
	void sinTokenDevuelve401() throws Exception {
		mvc.perform(post("/api/productos").contentType(MediaType.APPLICATION_JSON).content(NUEVO))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void unUsuarioNormalNoPuedeCrear403() throws Exception {
		mvc.perform(post("/api/productos").with(usuario("ana", "user"))
				.contentType(MediaType.APPLICATION_JSON).content(NUEVO))
				.andExpect(status().isForbidden());
	}

	@Test
	void unAdminPuedeCrear() throws Exception {
		mvc.perform(post("/api/productos").with(usuario("admin", "user", "admin"))
				.contentType(MediaType.APPLICATION_JSON).content(NUEVO))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.nombre").value("Monitor"));
	}

	@Test
	void meDevuelveLosRolesDelToken() throws Exception {
		mvc.perform(get("/api/me").with(usuario("ana", "user")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.authorities[0]").value("ROLE_user"));
	}
}
