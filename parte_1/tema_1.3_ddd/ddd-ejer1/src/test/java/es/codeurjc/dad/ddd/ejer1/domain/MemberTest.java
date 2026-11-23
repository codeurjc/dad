package es.codeurjc.dad.ddd.ejer1.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MemberTest {

	private static final LocalDate TODAY = LocalDate.of(2026, 11, 2);

	private Member ana;

	@BeforeEach
	void setUp() {
		ana = new Member(new MemberId("m-1"), "Ana");
	}

	@Test
	void regla1_maximoTresPrestamosActivos() {
		ana.borrow(new CopyId("c-1"), TODAY);
		ana.borrow(new CopyId("c-2"), TODAY);
		ana.borrow(new CopyId("c-3"), TODAY);

		assertThrows(LibraryException.class, () -> ana.borrow(new CopyId("c-4"), TODAY));
	}

	@Test
	void regla2_unPrestamoDuraCatorceDias() {
		Loan loan = ana.borrow(new CopyId("c-1"), TODAY);
		assertEquals(TODAY.plusDays(14), loan.dueDate());
	}

	@Test
	void regla3_conPrestamosVencidosNoSePuedePedirOtro() {
		ana.borrow(new CopyId("c-1"), TODAY);

		LocalDate dentroDeQuinceDias = TODAY.plusDays(15);
		assertFalse(ana.canBorrow(dentroDeQuinceDias));
		assertThrows(LibraryException.class, () -> ana.borrow(new CopyId("c-2"), dentroDeQuinceDias));
	}

	@Test
	void regla3_conPenalizacionPendienteNoSePuedePedir() {
		ana.borrow(new CopyId("c-1"), TODAY);
		ana.giveBack(new CopyId("c-1"), TODAY.plusDays(16));

		assertThrows(LibraryException.class, () -> ana.borrow(new CopyId("c-2"), TODAY.plusDays(16)));

		ana.payPenalty(Money.euros("1.00"));
		assertTrue(ana.canBorrow(TODAY.plusDays(16)));
	}

	@Test
	void regla4_penalizacionDeCincuentaCentimosPorDia() {
		ana.borrow(new CopyId("c-1"), TODAY);

		Money penalty = ana.giveBack(new CopyId("c-1"), TODAY.plusDays(14 + 3));

		assertEquals(Money.euros("1.50"), penalty);
		assertEquals(Money.euros("1.50"), ana.pendingPenalty());
	}

	@Test
	void regla4_devolverATiempoNoPenaliza() {
		ana.borrow(new CopyId("c-1"), TODAY);
		assertEquals(Money.ZERO, ana.giveBack(new CopyId("c-1"), TODAY.plusDays(14)));
	}

	@Test
	void regla6_soloSePuedeRenovarUnaVez() {
		ana.borrow(new CopyId("c-1"), TODAY);
		ana.renew(new CopyId("c-1"), TODAY.plusDays(10));

		assertEquals(TODAY.plusDays(28), ana.activeLoans().get(0).dueDate());
		assertThrows(LibraryException.class, () -> ana.renew(new CopyId("c-1"), TODAY.plusDays(20)));
	}

	@Test
	void regla6_noSePuedeRenovarUnPrestamoVencido() {
		ana.borrow(new CopyId("c-1"), TODAY);
		assertThrows(LibraryException.class, () -> ana.renew(new CopyId("c-1"), TODAY.plusDays(15)));
	}

	@Test
	void devolverTardeGeneraLosEventosCorrespondientes() {
		ana.borrow(new CopyId("c-1"), TODAY);
		ana.giveBack(new CopyId("c-1"), TODAY.plusDays(20));

		List<DomainEvent> events = ana.pullEvents();
		assertEquals(3, events.size());
		assertInstanceOf(DomainEvent.CopyBorrowed.class, events.get(0));
		assertInstanceOf(DomainEvent.CopyReturned.class, events.get(1));
		assertInstanceOf(DomainEvent.PenaltyImposed.class, events.get(2));
	}

	@Test
	void noSePuedePagarMasDeLoQueSeDebe() {
		assertThrows(LibraryException.class, () -> ana.payPenalty(Money.euros("1")));
	}
}
