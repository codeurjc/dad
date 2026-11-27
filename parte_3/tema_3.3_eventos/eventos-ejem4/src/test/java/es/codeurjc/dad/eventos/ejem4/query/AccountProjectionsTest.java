package es.codeurjc.dad.eventos.ejem4.query;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigDecimal;
import java.util.List;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.eventos.ejem4.application.AccountCommandService;
import es.codeurjc.dad.eventos.ejem4.eventstore.InMemoryEventStore;

class AccountProjectionsTest {

	@Test
	void lasProyeccionesSeActualizanConLosComandos() {
		InMemoryEventStore store = new InMemoryEventStore();
		AccountProjections projections = new AccountProjections();
		store.subscribe(projections::on);
		AccountCommandService commands = new AccountCommandService(store);

		String ana = commands.openAccount("Ana");
		commands.deposit(ana, new BigDecimal("100"));
		commands.withdraw(ana, new BigDecimal("40"));
		String luis = commands.openAccount("Luis");
		commands.deposit(luis, new BigDecimal("500"));

		AccountSummary summary = projections.summary(ana).orElseThrow();
		assertEquals(new BigDecimal("60"), summary.balance());
		assertEquals(2, summary.movements());

		List<Movement> statement = projections.statement(ana);
		assertEquals(new BigDecimal("-40"), statement.get(1).amount());

		assertEquals("Luis", projections.richest(1).get(0).owner());
	}

	@Test
	void unaProyeccionNuevaSePuedeConstruirConLaHistoriaCompleta() {
		InMemoryEventStore store = new InMemoryEventStore();
		AccountCommandService commands = new AccountCommandService(store);
		String ana = commands.openAccount("Ana");
		commands.deposit(ana, new BigDecimal("100"));

		// La proyección se crea DESPUÉS: la alimentamos con todos los eventos pasados
		AccountProjections late = new AccountProjections();
		store.load(ana).forEach(late::on);

		assertEquals(new BigDecimal("100"), late.summary(ana).orElseThrow().balance());
	}
}
