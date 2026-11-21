package es.codeurjc.dad.micro.ejer1.libros;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Version;

@Entity
public class Book {

	@Id
	private String isbn;

	private String title;

	private String author;

	private int totalCopies;

	private int availableCopies;

	/** Bloqueo optimista: dos préstamos simultáneos del último ejemplar no pueden pasar los dos. */
	@Version
	private Long version;

	protected Book() {
	}

	public Book(String isbn, String title, String author, int copies) {
		this.isbn = isbn;
		this.title = title;
		this.author = author;
		this.totalCopies = copies;
		this.availableCopies = copies;
	}

	public void checkout() {
		if (availableCopies == 0) {
			throw new IllegalStateException("No quedan ejemplares disponibles de " + title);
		}
		availableCopies--;
	}

	public void giveBack() {
		if (availableCopies == totalCopies) {
			throw new IllegalStateException("Todos los ejemplares de " + title + " ya estaban en la biblioteca");
		}
		availableCopies++;
	}

	public String getIsbn() {
		return isbn;
	}

	public String getTitle() {
		return title;
	}

	public String getAuthor() {
		return author;
	}

	public int getTotalCopies() {
		return totalCopies;
	}

	public int getAvailableCopies() {
		return availableCopies;
	}
}
