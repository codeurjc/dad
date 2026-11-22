package es.codeurjc.dad.seg.ejer1;

import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

/** Datos iniciales: pedido 1 de ana, pedido 2 de luis */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PedidoControllerTest {

	@Autowired
	private MockMvc mvc;

	@Autowired
	private PedidoService service;

	private static JwtRequestPostProcessor usuario(String nombre, String... roles) {
		return jwt()
				.jwt(t -> t.subject(nombre).claim("preferred_username", nombre)
						.claim("realm_access", Map.of("roles", List.of(roles))))
				.authorities(new KeycloakRolesConverter());
	}

	private static final JwtRequestPostProcessor ANA = usuario("ana", "user");
	private static final JwtRequestPostProcessor LUIS = usuario("luis", "user");
	private static final JwtRequestPostProcessor SOPORTE = usuario("soporte", "user", "soporte");

	@Test
	void sinTokenDevuelve401() throws Exception {
		mvc.perform(get("/api/pedidos")).andExpect(status().isUnauthorized());
	}

	@Test
	void cadaUsuarioSoloVeSusPedidos() throws Exception {
		mvc.perform(get("/api/pedidos").with(ANA))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$", hasSize(1)))
				.andExpect(jsonPath("$[*].propietario", everyItem(is("ana"))));
	}

	@Test
	void soporteVeTodos() throws Exception {
		mvc.perform(get("/api/pedidos").with(SOPORTE)).andExpect(jsonPath("$", hasSize(2)));
	}

	@Test
	void unPedidoAjenoDevuelve404ComoSiNoExistiera() throws Exception {
		mvc.perform(get("/api/pedidos/2").with(ANA)).andExpect(status().isNotFound());
		mvc.perform(get("/api/pedidos/99").with(ANA)).andExpect(status().isNotFound());
		mvc.perform(get("/api/pedidos/2").with(LUIS)).andExpect(status().isOk());
	}

	@Test
	void elPropietarioSaleDelTokenNoDelCuerpo() throws Exception {
		mvc.perform(post("/api/pedidos").with(ANA).contentType(MediaType.APPLICATION_JSON)
				.content("{\"producto\":\"raton\",\"unidades\":1,\"propietario\":\"luis\",\"estado\":\"ENVIADO\"}"))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.propietario").value("ana"))
				.andExpect(jsonPath("$.estado").value("PENDIENTE"));
	}

	@Test
	void noSePuedeCancelarUnPedidoAjeno() throws Exception {
		mvc.perform(delete("/api/pedidos/2").with(ANA)).andExpect(status().isNotFound());
		mvc.perform(get("/api/pedidos/2").with(LUIS)).andExpect(jsonPath("$.estado").value("PENDIENTE"));
	}

	@Test
	void elPropietarioCancelaSoloSiEstaPendiente() throws Exception {
		mvc.perform(delete("/api/pedidos/1").with(ANA))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.estado").value("CANCELADO"));
		service.enviar(2);
		mvc.perform(delete("/api/pedidos/2").with(LUIS)).andExpect(status().isConflict());
	}

	@Test
	void unTokenSinRolUserDevuelve403() throws Exception {
		mvc.perform(get("/api/pedidos").with(usuario("bot"))).andExpect(status().isForbidden());
	}
}
