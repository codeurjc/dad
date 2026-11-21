package es.codeurjc.dad.micro.ejer1.prestamos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import es.codeurjc.dad.micro.ejer1.prestamos.LibrosClient.LibrosUnavailableException;
import es.codeurjc.dad.micro.ejer1.prestamos.LibrosClient.NoCopiesAvailableException;

/**
 * Comprobacion minima del servicio de prestamos con un doble del servicio de
 * libros (no hace falta arrancarlo).
 */
@SpringBootTest
class SmokeTest {

	/** Servicio de libros falso, en memoria. */
	static class FakeLibros implements LibrosClient {

		final Map<String, Integer> copies = new HashMap<>(Map.of("A", 5, "B", 1));
		boolean down;

		@Override
		public BookInfo checkout(String isbn) {
			if (down) {
				throw new LibrosUnavailableException(new RuntimeException("caído"));
			}
			int n = copies.getOrDefault(isbn, -1);
			if (n < 0) {
				throw new BookNotFoundException(isbn);
			}
			if (n == 0) {
				throw new NoCopiesAvailableException("sin ejemplares");
			}
			copies.put(isbn, n - 1);
			return new BookInfo(isbn, "Libro " + isbn, n - 1);
		}

		@Override
		public void giveBack(String isbn) {
			copies.merge(isbn, 1, Integer::sum);
		}
	}

	@TestConfiguration
	static class Config {

		@Bean
		@Primary
		FakeLibros fakeLibros() {
			return new FakeLibros();
		}
	}

	@Autowired
	private LoanService loans;

	@Autowired
	private FakeLibros libros;

	@Test
	void unSocioNoPuedeTenerMasDeTresPrestamos() {
		for (int i = 0; i < 3; i++) {
			loans.borrow("A", "ana");
		}
		assertThrows(IllegalStateException.class, () -> loans.borrow("A", "ana"));
		assertEquals(2, libros.copies.get("A"), "el cuarto préstamo no ha llegado a reservar ejemplar");
	}

	@Test
	void devolverLiberaElEjemplar() {
		Loan loan = loans.borrow("B", "luis");
		assertThrows(NoCopiesAvailableException.class, () -> loans.borrow("B", "eva"));

		loans.giveBack(loan.getId());
		assertEquals(1, libros.copies.get("B"));
	}

	@Test
	void siLibrosEstaCaidoLasConsultasSiguenFuncionando() {
		loans.borrow("A", "pepe");
		libros.down = true;
		try {
			assertThrows(LibrosUnavailableException.class, () -> loans.borrow("A", "pepe"));
			assertEquals(1, loans.loansOf("pepe").size());
		} finally {
			libros.down = false;
		}
	}
}
