package es.codeurjc.dad.micro.ejer1.prestamos;

import java.time.LocalDate;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

@Entity
public class Loan {

	@Id
	@GeneratedValue
	private Long id;

	private String isbn;

	/** Copia del título: consultar los préstamos no necesita al servicio de libros. */
	private String title;

	private String memberId;

	private LocalDate loanDate;

	private LocalDate returnDate;

	protected Loan() {
	}

	public Loan(String isbn, String title, String memberId, LocalDate loanDate) {
		this.isbn = isbn;
		this.title = title;
		this.memberId = memberId;
		this.loanDate = loanDate;
	}

	public boolean isActive() {
		return returnDate == null;
	}

	public void markReturned(LocalDate date) {
		if (!isActive()) {
			throw new IllegalStateException("El préstamo " + id + " ya estaba devuelto");
		}
		this.returnDate = date;
	}

	public Long getId() {
		return id;
	}

	public String getIsbn() {
		return isbn;
	}

	public String getTitle() {
		return title;
	}

	public String getMemberId() {
		return memberId;
	}

	public LocalDate getLoanDate() {
		return loanDate;
	}

	public LocalDate getReturnDate() {
		return returnDate;
	}
}
