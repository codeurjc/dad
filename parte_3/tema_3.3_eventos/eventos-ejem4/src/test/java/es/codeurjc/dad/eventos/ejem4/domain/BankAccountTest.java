package es.codeurjc.dad.eventos.ejem4.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.AccountOpened;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.MoneyDeposited;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.MoneyWithdrawn;

class BankAccountTest {

	private static final Instant T = Instant.parse("2026-11-02T10:00:00Z");

	@Test
	void elEstadoSeReconstruyeAPartirDeLosEventos() {
		BankAccount account = BankAccount.replay(List.of(
				new AccountOpened("A1", "Ana", T),
				new MoneyDeposited("A1", new BigDecimal("100"), T),
				new MoneyWithdrawn("A1", new BigDecimal("30"), T),
				new MoneyDeposited("A1", new BigDecimal("5"), T)));

		assertEquals(new BigDecimal("75"), account.balance());
		assertEquals(4, account.version());
	}

	@Test
	void unComandoValidoGeneraUnEvento() {
		BankAccount account = BankAccount.replay(List.of(new AccountOpened("A1", "Ana", T)));
		account.deposit(new BigDecimal("50"));

		assertEquals(1, account.persistedVersion(), "version guardada antes del comando");
		List<AccountEvent> events = account.pullPendingEvents();
		assertEquals(1, events.size());
		assertInstanceOf(MoneyDeposited.class, events.get(0));
	}

	@Test
	void unComandoInvalidoNoGeneraEventos() {
		BankAccount account = BankAccount.replay(List.of(new AccountOpened("A1", "Ana", T)));

		assertThrows(AccountException.class, () -> account.withdraw(new BigDecimal("1")));
		assertEquals(0, account.pullPendingEvents().size());
	}

	@Test
	void soloSeCierraConSaldoCero() {
		BankAccount account = BankAccount.replay(List.of(
				new AccountOpened("A1", "Ana", T), new MoneyDeposited("A1", BigDecimal.TEN, T)));

		assertThrows(AccountException.class, account::close);
		account.withdraw(BigDecimal.TEN);
		account.close();
		assertThrows(AccountException.class, () -> account.deposit(BigDecimal.ONE));
	}
}
