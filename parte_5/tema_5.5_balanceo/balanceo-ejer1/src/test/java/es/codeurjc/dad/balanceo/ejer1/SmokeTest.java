package es.codeurjc.dad.balanceo.ejer1;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import es.codeurjc.dad.balanceo.ejer1.lb.LoadBalancer;

/**
 * Comprobacion minima: el contexto arranca con los servidores configurados.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private LoadBalancer lb;

	@Test
	void seConfiguranLosTresServidores() {
		assertEquals(3, lb.backends().size());
	}
}
