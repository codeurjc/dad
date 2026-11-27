package es.codeurjc.dad.eventos.ejem4;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigDecimal;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import es.codeurjc.dad.eventos.ejem4.application.AccountCommandService;
import es.codeurjc.dad.eventos.ejem4.query.AccountProjections;

/**
 * Comprobacion minima: el contexto arranca y la proyeccion refleja los comandos.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private AccountCommandService commands;

	@Autowired
	private AccountProjections projections;

	@Test
	void unIngresoSeVeEnElModeloDeLectura() {
		String id = commands.openAccount("Ana");
		commands.deposit(id, new BigDecimal("25"));

		assertEquals(new BigDecimal("25"), projections.summary(id).orElseThrow().balance());
	}
}
