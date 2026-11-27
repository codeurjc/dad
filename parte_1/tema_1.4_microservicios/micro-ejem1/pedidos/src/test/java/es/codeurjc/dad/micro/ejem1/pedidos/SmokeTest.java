package es.codeurjc.dad.micro.ejem1.pedidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Comprobacion minima: el contexto arranca y se puede crear un pedido. El
 * catalogo se sustituye por un doble de prueba: no hace falta arrancarlo.
 */
@SpringBootTest
class SmokeTest {

	@TestConfiguration
	static class FakeCatalog {

		@Bean
		@Primary
		CatalogClient fakeCatalogClient() {
			return id -> id == 1 ? Optional.of(new ProductInfo(1L, "Libro", new BigDecimal("10.00"), 5))
					: Optional.empty();
		}
	}

	@Autowired
	private OrderService orders;

	@Test
	void sePuedeHacerUnPedidoDeUnProductoConStock() {
		Order order = orders.placeOrder(1L, 2);
		assertEquals(new BigDecimal("20.00"), order.getTotal());
	}

	@Test
	void noSePuedePedirMasDeLoQueHay() {
		assertThrows(IllegalStateException.class, () -> orders.placeOrder(1L, 6));
	}
}
