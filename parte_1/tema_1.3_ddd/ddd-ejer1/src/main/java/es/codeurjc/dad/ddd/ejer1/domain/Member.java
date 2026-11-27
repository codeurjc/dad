package es.codeurjc.dad.ddd.ejer1.domain;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import es.codeurjc.dad.ddd.ejer1.domain.DomainEvent.CopyBorrowed;
import es.codeurjc.dad.ddd.ejer1.domain.DomainEvent.CopyReturned;
import es.codeurjc.dad.ddd.ejer1.domain.DomainEvent.LoanRenewed;
import es.codeurjc.dad.ddd.ejer1.domain.DomainEvent.PenaltyImposed;

/**
 * Agregado Socio. Raíz de un agregado que contiene sus préstamos activos.
 *
 * ¿Por qué los préstamos están DENTRO del socio? Porque las reglas 1, 3 y 4
 * ("máximo 3 préstamos", "no puede pedir si tiene vencidos o penalización",
 * "penalización al devolver tarde") afectan a la vez al socio y a todos sus
 * préstamos: para garantizarlas de forma consistente tienen que estar en el
 * mismo agregado.
 *
 * La regla 5 ("un ejemplar solo puede estar prestado una vez") pertenece al
 * agregado Copy.
 */
public class Member {

	public static final int MAX_ACTIVE_LOANS = 3;
	public static final Money PENALTY_PER_DAY = Money.euros("0.50");

	private final MemberId id;
	private final String name;
	private final List<Loan> activeLoans = new ArrayList<>();
	private Money pendingPenalty = Money.ZERO;
	private final List<DomainEvent> events = new ArrayList<>();

	public Member(MemberId id, String name) {
		this.id = Objects.requireNonNull(id);
		if (name == null || name.isBlank()) {
			throw new IllegalArgumentException("El nombre es obligatorio");
		}
		this.name = name;
	}

	/** Reglas 1, 2 y 3. */
	public Loan borrow(CopyId copyId, LocalDate today) {
		if (!canBorrow(today)) {
			throw new LibraryException(reasonCannotBorrow(today));
		}
		if (findLoan(copyId).isPresent()) {
			throw new LibraryException("El socio ya tiene prestado el ejemplar " + copyId);
		}
		Loan loan = new Loan(copyId, today);
		activeLoans.add(loan);
		events.add(new CopyBorrowed(id, copyId, loan.dueDate()));
		return loan;
	}

	/** Regla 6. */
	public void renew(CopyId copyId, LocalDate today) {
		Loan loan = requireLoan(copyId);
		loan.renew(today);
		events.add(new LoanRenewed(id, copyId, loan.dueDate()));
	}

	/** Regla 4. Devuelve la penalización generada (cero si llega a tiempo). */
	public Money giveBack(CopyId copyId, LocalDate today) {
		Loan loan = requireLoan(copyId);
		activeLoans.remove(loan);

		long daysLate = loan.daysLate(today);
		events.add(new CopyReturned(id, copyId, daysLate));

		Money penalty = PENALTY_PER_DAY.times(daysLate);
		if (!penalty.isZero()) {
			pendingPenalty = pendingPenalty.plus(penalty);
			events.add(new PenaltyImposed(id, penalty));
		}
		return penalty;
	}

	public void payPenalty(Money amount) {
		if (amount.isGreaterThan(pendingPenalty)) {
			throw new LibraryException("Se intenta pagar " + amount + " pero solo se deben " + pendingPenalty);
		}
		pendingPenalty = pendingPenalty.minus(amount);
	}

	public boolean canBorrow(LocalDate today) {
		return reasonCannotBorrow(today) == null;
	}

	private String reasonCannotBorrow(LocalDate today) {
		if (activeLoans.size() >= MAX_ACTIVE_LOANS) {
			return "El socio ya tiene " + MAX_ACTIVE_LOANS + " préstamos activos";
		}
		if (!pendingPenalty.isZero()) {
			return "El socio tiene una penalización pendiente de " + pendingPenalty;
		}
		if (activeLoans.stream().anyMatch(l -> l.isOverdue(today))) {
			return "El socio tiene préstamos vencidos";
		}
		return null;
	}

	private Optional<Loan> findLoan(CopyId copyId) {
		return activeLoans.stream().filter(l -> l.copyId().equals(copyId)).findFirst();
	}

	private Loan requireLoan(CopyId copyId) {
		return findLoan(copyId)
				.orElseThrow(() -> new LibraryException("El socio no tiene prestado el ejemplar " + copyId));
	}

	public List<DomainEvent> pullEvents() {
		List<DomainEvent> copy = List.copyOf(events);
		events.clear();
		return copy;
	}

	public MemberId id() {
		return id;
	}

	public String name() {
		return name;
	}

	public List<Loan> activeLoans() {
		return List.copyOf(activeLoans);
	}

	public Money pendingPenalty() {
		return pendingPenalty;
	}
}
