package es.codeurjc.dad.micro.ejem1.catalogo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Comprobacion minima: el contexto arranca con los datos de ejemplo.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private ProductRepository products;

	@Test
	void hayTresProductos() {
		assertEquals(3, products.count());
	}
}
