package es.codeurjc.dad.eventos.ejem4.domain;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Eventos de una cuenta bancaria. En event sourcing estos eventos SON el
 * estado: no guardamos el saldo, guardamos lo que ha pasado.
 */
public sealed interface AccountEvent {

	String accountId();

	Instant occurredAt();

	record AccountOpened(String accountId, String owner, Instant occurredAt) implements AccountEvent {
	}

	record MoneyDeposited(String accountId, BigDecimal amount, Instant occurredAt) implements AccountEvent {
	}

	record MoneyWithdrawn(String accountId, BigDecimal amount, Instant occurredAt) implements AccountEvent {
	}

	record AccountClosed(String accountId, Instant occurredAt) implements AccountEvent {
	}
}
