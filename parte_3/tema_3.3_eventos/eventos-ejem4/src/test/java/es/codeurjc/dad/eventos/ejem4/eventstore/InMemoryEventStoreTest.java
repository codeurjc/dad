package es.codeurjc.dad.eventos.ejem4.eventstore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.AccountOpened;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.MoneyDeposited;

class InMemoryEventStoreTest {

	private final InMemoryEventStore store = new InMemoryEventStore();

	@Test
	void dosEscriturasConcurrentesNoPuedenPisarse() {
		store.append("A1", 0, List.of(new AccountOpened("A1", "Ana", Instant.now())));

		// Dos peticiones leen la cuenta en la versión 1...
		store.append("A1", 1, List.of(new MoneyDeposited("A1", BigDecimal.TEN, Instant.now())));
		// ...la segunda intenta escribir creyendo que sigue en la versión 1
		assertThrows(ConcurrencyException.class,
				() -> store.append("A1", 1, List.of(new MoneyDeposited("A1", BigDecimal.ONE, Instant.now()))));

		assertEquals(2, store.load("A1").size());
	}

	@Test
	void losSuscriptoresRecibenCadaEventoGuardado() {
		List<AccountEvent> received = new ArrayList<>();
		store.subscribe(received::add);

		store.append("A1", 0, List.of(new AccountOpened("A1", "Ana", Instant.now()),
				new MoneyDeposited("A1", BigDecimal.TEN, Instant.now())));

		assertEquals(2, received.size());
	}
}
