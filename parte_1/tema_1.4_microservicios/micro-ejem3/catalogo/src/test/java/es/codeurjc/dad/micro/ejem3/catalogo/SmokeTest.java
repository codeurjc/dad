package es.codeurjc.dad.micro.ejem3.catalogo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Comprobacion minima: el contexto arranca y, sin fallos inyectados, responde.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private ProductController controller;

	@Test
	void sinCaosDevuelveElProducto() throws InterruptedException {
		assertEquals(200, controller.product(1L).getStatusCode().value());
	}
}
