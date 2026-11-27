package es.codeurjc.dad.k8s.ejem1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

class HolaControllerTest {

	@Test
	void devuelveMensajeVersionYPod() {
		Map<String, Object> r = new HolaController("Hola DAD", "v2", "").hola();
		assertEquals("Hola DAD", r.get("mensaje"));
		assertEquals("v2", r.get("version"));
		assertFalse(((String) r.get("pod")).isBlank());
		assertEquals(false, r.get("apiKeyConfigurada"));
	}

	@Test
	void nuncaDevuelveElSecreto() {
		Map<String, Object> r = new HolaController("Hola", "v1", "s3cr3t0").hola();
		assertTrue((Boolean) r.get("apiKeyConfigurada"));
		assertFalse(r.toString().contains("s3cr3t0"));
	}
}
