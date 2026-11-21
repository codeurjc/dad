package es.codeurjc.dad.ddd.ejer1.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;

class LendingPolicyTest {

	private static final LocalDate TODAY = LocalDate.of(2026, 11, 2);

	private final LendingPolicy lending = new LendingPolicy();
	private final Member ana = new Member(new MemberId("m-1"), "Ana");
	private final Member luis = new Member(new MemberId("m-2"), "Luis");
	private final Copy copy = new Copy(new CopyId("c-1"), "978-0321125217", "Domain-Driven Design");

	@Test
	void regla5_unEjemplarNoSePuedePrestarDosVeces() {
		lending.lend(ana, copy, TODAY);

		assertFalse(copy.isAvailable());
		assertThrows(LibraryException.class, () -> lending.lend(luis, copy, TODAY));
		assertTrue(luis.activeLoans().isEmpty(), "si falla, el socio no se modifica");
	}

	@Test
	void alDevolverElEjemplarVuelveAEstarDisponible() {
		lending.lend(ana, copy, TODAY);
		lending.giveBack(ana, copy, TODAY.plusDays(1));

		assertTrue(copy.isAvailable());
		assertEquals(0, ana.activeLoans().size());
	}
}
