package es.codeurjc.dad.ddd.ejem1.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CustomerTest {

	private final Address address = new Address("C/ Tulipán", "Móstoles", "28933", "España");

	@Test
	void laIdentidadNoDependeDeLosAtributos() {
		CustomerId id = CustomerId.newId();
		Customer c1 = new Customer(id, "Ana", new EmailAddress("ana@urjc.es"), address);
		Customer c2 = new Customer(id, "Ana García", new EmailAddress("ana@gmail.com"), address);

		assertEquals(c1, c2);
	}

	@Test
	void dosClientesConLosMismosDatosPeroDistintoIdSonDistintos() {
		Customer c1 = new Customer(CustomerId.newId(), "Ana", new EmailAddress("ana@urjc.es"), address);
		Customer c2 = new Customer(CustomerId.newId(), "Ana", new EmailAddress("ana@urjc.es"), address);

		assertNotEquals(c1, c2);
	}

	@Test
	void unClienteEsVipCuandoSuperaElUmbral() {
		Customer c = new Customer(CustomerId.newId(), "Ana", new EmailAddress("ana@urjc.es"), address);
		c.registerPurchase(Money.euros("1000"));
		assertFalse(c.isVip());

		c.registerPurchase(Money.euros("0.01"));
		assertTrue(c.isVip());
	}
}
