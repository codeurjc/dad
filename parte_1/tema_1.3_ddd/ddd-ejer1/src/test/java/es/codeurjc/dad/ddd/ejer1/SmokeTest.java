package es.codeurjc.dad.ddd.ejer1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import es.codeurjc.dad.ddd.ejer1.application.LibraryService;
import es.codeurjc.dad.ddd.ejer1.domain.CopyId;
import es.codeurjc.dad.ddd.ejer1.domain.LibraryException;
import es.codeurjc.dad.ddd.ejer1.domain.MemberId;

/**
 * Comprobacion minima: el contexto arranca con los datos de ejemplo y se
 * puede prestar un ejemplar.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private LibraryService library;

	@Test
	void sePuedePrestarUnEjemplarUnaSolaVez() {
		library.borrow(new MemberId("m-1"), new CopyId("c-5"));

		assertEquals(1, library.findMember(new MemberId("m-1")).activeLoans().size());
		assertThrows(LibraryException.class, () -> library.borrow(new MemberId("m-2"), new CopyId("c-5")));
	}
}
