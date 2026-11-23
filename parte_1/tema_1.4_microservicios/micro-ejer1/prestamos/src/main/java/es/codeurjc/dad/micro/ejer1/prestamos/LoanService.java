package es.codeurjc.dad.micro.ejer1.prestamos;

import java.time.LocalDate;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Préstamo = cambio en DOS servicios (libros: un ejemplar menos; préstamos:
 * un préstamo más). No hay transacción común: si el segundo paso falla,
 * COMPENSAMOS el primero (es una saga muy pequeña; ver tema 3.3).
 */
@Service
public class LoanService {

	public static final int MAX_ACTIVE_LOANS = 3;

	private static final Logger log = LoggerFactory.getLogger(LoanService.class);

	private final LoanRepository loans;
	private final LibrosClient libros;

	public LoanService(LoanRepository loans, LibrosClient libros) {
		this.loans = loans;
		this.libros = libros;
	}

	public Loan borrow(String isbn, String memberId) {
		// 1. Reglas locales: no necesitan a nadie más
		if (loans.countByMemberIdAndReturnDateIsNull(memberId) >= MAX_ACTIVE_LOANS) {
			throw new IllegalStateException("El socio " + memberId + " ya tiene " + MAX_ACTIVE_LOANS + " préstamos");
		}
		// 2. Paso remoto
		BookInfo book = libros.checkout(isbn);
		// 3. Paso local; si falla, compensamos el remoto
		try {
			return loans.save(new Loan(isbn, book.title(), memberId, LocalDate.now()));
		} catch (RuntimeException e) {
			log.error("No se pudo guardar el préstamo: se devuelve el ejemplar de {}", isbn, e);
			libros.giveBack(isbn);
			throw e;
		}
	}

	public Loan giveBack(Long loanId) {
		Loan loan = loans.findById(loanId)
				.orElseThrow(() -> new IllegalArgumentException("No existe el préstamo " + loanId));
		if (!loan.isActive()) {
			throw new IllegalStateException("El préstamo " + loanId + " ya estaba devuelto");
		}
		libros.giveBack(loan.getIsbn());
		loan.markReturned(LocalDate.now());
		return loans.save(loan);
	}

	/** Solo datos locales: funciona aunque el servicio de libros esté caído. */
	public List<Loan> loansOf(String memberId) {
		return loans.findByMemberId(memberId);
	}
}
