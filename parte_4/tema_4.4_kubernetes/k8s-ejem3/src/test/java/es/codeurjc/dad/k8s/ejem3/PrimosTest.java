package es.codeurjc.dad.k8s.ejem3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PrimosTest {

	@Test
	void cuentaPrimos() {
		assertEquals(0, Primos.contarHasta(1));
		assertEquals(4, Primos.contarHasta(10));
		assertEquals(25, Primos.contarHasta(100));
		assertEquals(9592, Primos.contarHasta(100_000));
	}

	@Test
	void esPrimo() {
		assertTrue(Primos.esPrimo(2));
		assertTrue(Primos.esPrimo(7919));
		assertFalse(Primos.esPrimo(1));
		assertFalse(Primos.esPrimo(7917));
	}
}
