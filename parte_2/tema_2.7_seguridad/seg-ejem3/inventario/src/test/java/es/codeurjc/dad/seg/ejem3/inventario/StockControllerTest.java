package es.codeurjc.dad.seg.ejem3.inventario;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class StockControllerTest {

	@Autowired
	private MockMvc mvc;

	@Test
	void sinTokenDevuelve401() throws Exception {
		mvc.perform(get("/api/stock/teclado")).andExpect(status().isUnauthorized());
	}

	@Test
	void unTokenSinElRolDevuelve403() throws Exception {
		mvc.perform(get("/api/stock/teclado").with(jwt()
				.jwt(t -> t.claim("azp", "otro-servicio").claim("realm_access", Map.of("roles", List.of("user"))))
				.authorities(new KeycloakRolesConverter())))
				.andExpect(status().isForbidden());
	}

	@Test
	void elServicioDePedidosPuedeConsultar() throws Exception {
		mvc.perform(get("/api/stock/teclado").with(jwt()
				.jwt(t -> t.claim("azp", "pedidos-service")
						.claim("realm_access", Map.of("roles", List.of("inventario-lector"))))
				.authorities(new KeycloakRolesConverter())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.unidades").value(10));
	}
}
