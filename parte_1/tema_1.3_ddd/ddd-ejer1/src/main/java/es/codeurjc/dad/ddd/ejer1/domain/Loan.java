package es.codeurjc.dad.ddd.ejer1.domain;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * Préstamo: entidad interna del agregado Member. Su identidad local es el
 * ejemplar prestado (un socio no puede tener dos veces el mismo ejemplar).
 *
 * Es package-private en sus mutadores: solo Member puede cambiarla.
 */
public class Loan {

	public static final int LOAN_DAYS = 14;

	private final CopyId copyId;
	private final LocalDate startDate;
	private LocalDate dueDate;
	private boolean renewed;

	Loan(CopyId copyId, LocalDate startDate) {
		this.copyId = Objects.requireNonNull(copyId);
		this.startDate = Objects.requireNonNull(startDate);
		this.dueDate = startDate.plusDays(LOAN_DAYS);
	}

	boolean isOverdue(LocalDate today) {
		return today.isAfter(dueDate);
	}

	long daysLate(LocalDate returnDate) {
		return Math.max(0, ChronoUnit.DAYS.between(dueDate, returnDate));
	}

	void renew(LocalDate today) {
		if (renewed) {
			throw new LibraryException("El préstamo de " + copyId + " ya se renovó una vez");
		}
		if (isOverdue(today)) {
			throw new LibraryException("No se puede renovar un préstamo vencido");
		}
		dueDate = dueDate.plusDays(LOAN_DAYS);
		renewed = true;
	}

	public CopyId copyId() {
		return copyId;
	}

	public LocalDate startDate() {
		return startDate;
	}

	public LocalDate dueDate() {
		return dueDate;
	}

	public boolean renewed() {
		return renewed;
	}
}
