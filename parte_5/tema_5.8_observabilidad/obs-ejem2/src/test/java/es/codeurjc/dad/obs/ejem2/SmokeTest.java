package es.codeurjc.dad.obs.ejem2;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Comprobacion minima: el contexto arranca y las metricas propias estan registradas.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private MeterRegistry registry;

	@Test
	void lasMetricasDeNegocioEstanRegistradas() {
		assertNotNull(registry.find("shop.carts.active").gauge());
	}
}
