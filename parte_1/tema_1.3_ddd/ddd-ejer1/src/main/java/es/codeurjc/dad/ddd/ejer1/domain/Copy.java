package es.codeurjc.dad.ddd.ejer1.domain;

import java.util.Objects;
import java.util.Optional;

/**
 * Agregado Ejemplar: una copia física de un libro. Garantiza la regla 5: un
 * ejemplar solo puede estar prestado a un socio a la vez.
 *
 * Referencia al socio por identidad (MemberId), nunca con un objeto Member.
 */
public class Copy {

	private final CopyId id;
	private final String isbn;
	private final String title;
	private MemberId borrower;

	public Copy(CopyId id, String isbn, String title) {
		this.id = Objects.requireNonNull(id);
		this.isbn = Objects.requireNonNull(isbn);
		this.title = Objects.requireNonNull(title);
	}

	public void lendTo(MemberId memberId) {
		if (borrower != null) {
			throw new LibraryException("El ejemplar " + id + " ya está prestado");
		}
		borrower = Objects.requireNonNull(memberId);
	}

	public void returnedBy(MemberId memberId) {
		if (!memberId.equals(borrower)) {
			throw new LibraryException("El ejemplar " + id + " no está prestado a " + memberId);
		}
		borrower = null;
	}

	public boolean isAvailable() {
		return borrower == null;
	}

	public CopyId id() {
		return id;
	}

	public String isbn() {
		return isbn;
	}

	public String title() {
		return title;
	}

	public Optional<MemberId> borrower() {
		return Optional.ofNullable(borrower);
	}
}
