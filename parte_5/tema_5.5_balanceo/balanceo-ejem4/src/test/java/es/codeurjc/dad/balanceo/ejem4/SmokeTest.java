package es.codeurjc.dad.balanceo.ejem4;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Comprobacion minima: el contexto arranca y el endpoint de trabajo responde.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private WorkController controller;

	@Test
	void elEndpointDeTrabajoConsumeCpu() {
		assertTrue(controller.work(20).iterations() > 0);
	}
}
