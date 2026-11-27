package es.codeurjc.dad.ddd.ejem1.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Currency;

import org.junit.jupiter.api.Test;

class ValueObjectsTest {

	@Test
	void dosMoneyConElMismoValorSonIguales() {
		assertEquals(Money.euros("10"), Money.euros("10.00"));
	}

	@Test
	void sumarDevuelveUnObjetoNuevo() {
		Money diez = Money.euros("10");
		Money total = diez.plus(Money.euros("5.5"));

		assertEquals(Money.euros("15.50"), total);
		assertEquals(Money.euros("10"), diez, "el original no cambia: es inmutable");
	}

	@Test
	void noSePuedenSumarDivisasDistintas() {
		Money dolares = new Money(java.math.BigDecimal.ONE, Currency.getInstance("USD"));
		assertThrows(IllegalArgumentException.class, () -> Money.euros("1").plus(dolares));
	}

	@Test
	void noExisteDineroNegativo() {
		assertThrows(IllegalArgumentException.class, () -> Money.euros("-1"));
	}

	@Test
	void elEmailSeNormaliza() {
		assertEquals(new EmailAddress("ana@urjc.es"), new EmailAddress("  Ana@URJC.es "));
		assertEquals("urjc.es", new EmailAddress("ana@urjc.es").domain());
	}

	@Test
	void unEmailInvalidoNoSePuedeConstruir() {
		assertThrows(IllegalArgumentException.class, () -> new EmailAddress("ana.urjc.es"));
	}

	@Test
	void cambiarLaCalleCreaOtraDireccion() {
		Address a = new Address("C/ Tulipán", "Móstoles", "28933", "España");
		Address b = a.withStreet("C/ Camino del Molino");
		assertNotEquals(a, b);
		assertTrue(b.street().contains("Molino"));
	}
}
