package es.codeurjc.dad.micro.ejem3.pedidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import es.codeurjc.dad.micro.ejem3.pedidos.resilience.CircuitBreaker;

/**
 * Comprobacion minima: el contexto arranca y, con el catalogo apagado (no se
 * arranca en el test), la llamada falla de forma controlada.
 */
@SpringBootTest(properties = { "catalogo.url=http://localhost:1", "catalogo.retry.initial-backoff=1ms" })
class SmokeTest {

	@Autowired
	private ResilientCatalogClient catalog;

	@Test
	void sinCatalogoYSinCacheSeLanzaCatalogUnavailable() {
		assertThrows(CatalogUnavailableException.class, () -> catalog.findProduct(1L));
		assertEquals(CircuitBreaker.State.CLOSED, catalog.circuitState(), "3 fallos de una ventana de 10");
	}
}
