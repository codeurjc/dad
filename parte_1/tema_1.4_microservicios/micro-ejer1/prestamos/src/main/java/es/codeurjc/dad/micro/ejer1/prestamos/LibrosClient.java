package es.codeurjc.dad.micro.ejer1.prestamos;

/**
 * Puerto hacia el servicio de libros.
 */
public interface LibrosClient {

	/** Reserva un ejemplar. Lanza NoCopiesAvailableException o LibrosUnavailableException. */
	BookInfo checkout(String isbn);

	/** Devuelve un ejemplar a la biblioteca. */
	void giveBack(String isbn);

	class NoCopiesAvailableException extends RuntimeException {

		public NoCopiesAvailableException(String message) {
			super(message);
		}
	}

	class BookNotFoundException extends RuntimeException {

		public BookNotFoundException(String isbn) {
			super("No existe el libro " + isbn);
		}
	}

	class LibrosUnavailableException extends RuntimeException {

		public LibrosUnavailableException(Throwable cause) {
			super("El servicio de libros no está disponible", cause);
		}
	}
}
