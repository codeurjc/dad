package es.codeurjc.dad.micro.ejer1.libros;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Comprobacion minima: el contexto arranca y los ejemplares se prestan y devuelven.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private BookController books;

	@Test
	void noSePuedePrestarElUltimoEjemplarDosVeces() {
		books.checkout("978-1617294549");
		assertThrows(IllegalStateException.class, () -> books.checkout("978-1617294549"));
		assertEquals(1, books.giveBack("978-1617294549").getAvailableCopies());
	}
}
