package es.codeurjc.dad.ddd.ejer1.domain;

/**
 * Eventos de dominio del contexto de Préstamos. Es una interfaz sellada: el
 * compilador conoce todos los eventos posibles.
 */
public sealed interface DomainEvent {

	record CopyBorrowed(MemberId memberId, CopyId copyId, java.time.LocalDate dueDate) implements DomainEvent {
	}

	record LoanRenewed(MemberId memberId, CopyId copyId, java.time.LocalDate newDueDate) implements DomainEvent {
	}

	record CopyReturned(MemberId memberId, CopyId copyId, long daysLate) implements DomainEvent {
	}

	record PenaltyImposed(MemberId memberId, Money amount) implements DomainEvent {
	}
}
