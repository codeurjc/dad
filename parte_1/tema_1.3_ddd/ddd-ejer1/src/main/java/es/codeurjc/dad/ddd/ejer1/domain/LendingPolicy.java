package es.codeurjc.dad.ddd.ejer1.domain;

import java.time.LocalDate;

/**
 * Servicio de dominio: coordina una operación que involucra a DOS agregados
 * (Member y Copy) y que no pertenece de forma natural a ninguno de ellos.
 *
 * No tiene estado ni sabe nada de persistencia o transacciones: eso es
 * responsabilidad del servicio de aplicación.
 */
public class LendingPolicy {

	public Loan lend(Member member, Copy copy, LocalDate today) {
		if (!copy.isAvailable()) {
			throw new LibraryException("El ejemplar " + copy.id() + " no está disponible");
		}
		Loan loan = member.borrow(copy.id(), today);
		copy.lendTo(member.id());
		return loan;
	}

	public Money giveBack(Member member, Copy copy, LocalDate today) {
		Money penalty = member.giveBack(copy.id(), today);
		copy.returnedBy(member.id());
		return penalty;
	}
}
