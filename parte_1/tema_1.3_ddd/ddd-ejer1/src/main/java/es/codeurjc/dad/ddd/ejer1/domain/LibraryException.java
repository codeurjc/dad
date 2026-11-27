package es.codeurjc.dad.ddd.ejer1.domain;

/** Se lanza cuando una operación violaría una regla de la biblioteca. */
public class LibraryException extends RuntimeException {

	public LibraryException(String message) {
		super(message);
	}
}
